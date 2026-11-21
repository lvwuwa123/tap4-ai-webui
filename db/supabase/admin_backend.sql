-- Review admin backend for the static AI-tools directory (室内设计AI广场).
-- Run this AFTER create_table.sql / insert_category_data.sql / insert_data.sql / rls_policies.sql.
-- Safe to re-run. All privileged writes are wrapped in SECURITY DEFINER functions that
-- verify an admin password internally; the browser only uses the public anon key.

create extension if not exists pgcrypto with schema extensions;

-- Admin credential store. Password is stored as a bcrypt hash; table has RLS enabled
-- so it is not directly readable/writable by the public role.
create table if not exists public.admin_settings(
  id int primary key default 1,
  password_hash text not null,
  updated_at timestamptz default now()
);
alter table public.admin_settings enable row level security;

-- ONE-TIME: set the initial admin password. Replace 'CHANGE_ME' with your password,
-- run once, then delete this line. You can also change it later via admin_changepw().
-- insert into public.admin_settings(id, password_hash)
-- values (1, extensions.crypt('CHANGE_ME', extensions.gen_salt('bf', 10)))
-- on conflict (id) do update set password_hash=excluded.password_hash, updated_at=now();

-- Internal password check.
create or replace function public.admin_check(pw text)
returns boolean language sql security definer set search_path=public as $$
  select exists(select 1 from public.admin_settings s
                where s.id=1 and extensions.crypt(pw, s.password_hash)=s.password_hash);
$$;

create or replace function public.admin_stats(pw text)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then raise exception 'unauthorized'; end if;
  return jsonb_build_object(
    'total',    (select count(*) from public.submit),
    'pending',  (select count(*) from public.submit where status=0),
    'approved', (select count(*) from public.submit where status=1),
    'rejected', (select count(*) from public.submit where status=2),
    'live',     (select count(*) from public.web_navigation));
end; $$;

create or replace function public.admin_list(pw text)
returns table(id bigint, name text, url text, email text, created_at timestamptz, status integer)
language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then raise exception 'unauthorized'; end if;
  return query select s.id, s.name, s.url, s.email, s.created_at, s.status
    from public.submit s order by s.created_at desc;
end; $$;

create or replace function public.admin_categories(pw text)
returns table(name text, title text)
language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then raise exception 'unauthorized'; end if;
  return query select c.name, c.title from public.navigation_category c
    order by c.sort nulls last, c.name;
end; $$;

-- Approve a submission and publish it into the live catalogue.
create or replace function public.admin_approve(
  pw text, p_id bigint, p_category text, p_tag text, p_title text, p_content text, p_detail text)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v public.submit%rowtype;
begin
  if not public.admin_check(pw) then return jsonb_build_object('ok',false,'err','unauthorized'); end if;
  select * into v from public.submit where id=p_id;
  if not found then return jsonb_build_object('ok',false,'err','记录不存在'); end if;
  if exists(select 1 from public.web_navigation where name=v.name) then
    update public.submit set status=1 where id=p_id;
    return jsonb_build_object('ok',true,'warn','导航中已存在同名工具，仅标记为已处理');
  end if;
  insert into public.web_navigation(name,title,content,detail,url,tag_name,category_name,collection_time)
  values (v.name, coalesce(nullif(p_title,''),v.name), coalesce(p_content,''), coalesce(p_detail,''),
          v.url, coalesce(nullif(p_tag,''),'other'), coalesce(nullif(p_category,''),'other'), now());
  update public.submit set status=1 where id=p_id;
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.admin_reject(pw text, p_id bigint)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then return jsonb_build_object('ok',false,'err','unauthorized'); end if;
  update public.submit set status=2 where id=p_id;
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.admin_delete(pw text, p_id bigint)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then return jsonb_build_object('ok',false,'err','unauthorized'); end if;
  delete from public.submit where id=p_id;
  return jsonb_build_object('ok',true);
end; $$;

-- Full CRUD on the live catalogue.
-- NOTE: return type changed (added collection_time), so DROP the old signature first.
drop function if exists public.admin_nav_list(text);
create or replace function public.admin_nav_list(pw text)
returns table(name text,title text,content text,detail text,url text,thumbnail_url text,
              image_url text,category_name text,tag_name text,star_rating integer,
              collection_time timestamptz)
language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then raise exception 'unauthorized'; end if;
  return query select w.name,w.title,w.content,w.detail,w.url,w.thumbnail_url,w.image_url,
                     w.category_name,w.tag_name,w.star_rating,w.collection_time
    from public.web_navigation w
    order by w.collection_time desc nulls last, w.name;
end; $$;

create or replace function public.admin_nav_create(
  pw text,p_name text,p_title text,p_content text,p_detail text,p_url text,
  p_thumbnail text,p_category text,p_tag text)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then return jsonb_build_object('ok',false,'err','unauthorized'); end if;
  if p_name is null or btrim(p_name)='' then return jsonb_build_object('ok',false,'err','名称不能为空'); end if;
  if p_url is null or btrim(p_url)='' then return jsonb_build_object('ok',false,'err','网址不能为空'); end if;
  if exists(select 1 from public.web_navigation where name=p_name) then
    return jsonb_build_object('ok',false,'err','已存在同名工具（name 为主键）');
  end if;
  insert into public.web_navigation(name,title,content,detail,url,thumbnail_url,image_url,
                                    tag_name,category_name,collection_time)
  values (p_name, coalesce(nullif(p_title,''),p_name), coalesce(p_content,''), coalesce(p_detail,''),
          p_url, nullif(p_thumbnail,''), null, coalesce(nullif(p_tag,''),'other'),
          coalesce(nullif(p_category,''),'other'), now());
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.admin_nav_update(
  pw text,p_name text,p_new_name text,p_title text,p_content text,p_detail text,
  p_url text,p_thumbnail text,p_category text,p_tag text)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then return jsonb_build_object('ok',false,'err','unauthorized'); end if;
  if not exists(select 1 from public.web_navigation where name=p_name) then
    return jsonb_build_object('ok',false,'err','工具不存在');
  end if;
  if p_new_name is null or btrim(p_new_name)='' then return jsonb_build_object('ok',false,'err','名称不能为空'); end if;
  if p_new_name<>p_name and exists(select 1 from public.web_navigation where name=p_new_name) then
    return jsonb_build_object('ok',false,'err','新名称已存在');
  end if;
  update public.web_navigation set
    name=p_new_name,
    title=coalesce(nullif(p_title,''),p_new_name),
    content=coalesce(p_content,''),
    detail=coalesce(p_detail,''),
    url=coalesce(nullif(p_url,''),url),
    thumbnail_url=nullif(p_thumbnail,''),
    tag_name=coalesce(nullif(p_tag,''),'other'),
    category_name=coalesce(nullif(p_category,''),'other')
  where name=p_name;
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.admin_nav_delete(pw text, p_name text)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(pw) then return jsonb_build_object('ok',false,'err','unauthorized'); end if;
  delete from public.web_navigation where name=p_name;
  if found then return jsonb_build_object('ok',true); end if;
  return jsonb_build_object('ok',false,'err','工具不存在');
end; $$;

create or replace function public.admin_changepw(p_old text, p_new text)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  if not public.admin_check(p_old) then return jsonb_build_object('ok',false,'err','原密码错误'); end if;
  if length(p_new)<8 then return jsonb_build_object('ok',false,'err','新密码至少 8 位'); end if;
  update public.admin_settings set password_hash=extensions.crypt(p_new,extensions.gen_salt('bf',10)),
                                   updated_at=now() where id=1;
  return jsonb_build_object('ok',true);
end; $$;

-- Restrict execution to the public API roles; password is checked inside each function.
revoke all on function public.admin_check(text) from public;
revoke all on function public.admin_stats(text) from public;
revoke all on function public.admin_list(text) from public;
revoke all on function public.admin_categories(text) from public;
revoke all on function public.admin_approve(text,bigint,text,text,text,text,text) from public;
revoke all on function public.admin_reject(text,bigint) from public;
revoke all on function public.admin_delete(text,bigint) from public;
revoke all on function public.admin_nav_list(text) from public;
revoke all on function public.admin_nav_create(text,text,text,text,text,text,text,text,text) from public;
revoke all on function public.admin_nav_update(text,text,text,text,text,text,text,text,text,text) from public;
revoke all on function public.admin_nav_delete(text,text) from public;
revoke all on function public.admin_changepw(text,text) from public;

grant execute on function public.admin_check(text) to anon, authenticated;
grant execute on function public.admin_stats(text) to anon, authenticated;
grant execute on function public.admin_list(text) to anon, authenticated;
grant execute on function public.admin_categories(text) to anon, authenticated;
grant execute on function public.admin_approve(text,bigint,text,text,text,text,text) to anon, authenticated;
grant execute on function public.admin_reject(text,bigint) to anon, authenticated;
grant execute on function public.admin_delete(text,bigint) to anon, authenticated;
grant execute on function public.admin_nav_list(text) to anon, authenticated;
grant execute on function public.admin_nav_create(text,text,text,text,text,text,text,text,text) to anon, authenticated;
grant execute on function public.admin_nav_update(text,text,text,text,text,text,text,text,text,text) to anon, authenticated;
grant execute on function public.admin_nav_delete(text,text) to anon, authenticated;
grant execute on function public.admin_changepw(text,text) to anon, authenticated;

-- ============================================================
-- Thumbnail uploads: public Storage bucket + policies.
-- The admin page compresses a local image and uploads it with the
-- public anon key, then stores the returned public URL in thumbnail_url.
-- ============================================================
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('thumbs','thumbs',true,5242880,
        array['image/jpeg','image/png','image/webp','image/gif','image/avif'])
on conflict (id) do update set public=true,
  file_size_limit=excluded.file_size_limit,
  allowed_mime_types=excluded.allowed_mime_types;

drop policy if exists "thumb_public_read" on storage.objects;
create policy "thumb_public_read" on storage.objects for select to public
  using (bucket_id='thumbs');

drop policy if exists "thumb_anon_upload" on storage.objects;
create policy "thumb_anon_upload" on storage.objects for insert to anon, authenticated
  with check (bucket_id='thumbs');

drop policy if exists "thumb_anon_delete" on storage.objects;
create policy "thumb_anon_delete" on storage.objects for delete to anon, authenticated
  using (bucket_id='thumbs');
