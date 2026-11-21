-- Required when Row Level Security is enabled on this Supabase project.
-- Without these policies the public anon key reads zero rows and every page renders empty.
-- Run this AFTER create_table.sql / insert_category_data.sql / insert_data.sql.
-- Safe to re-run (DROP POLICY IF EXISTS + idempotent ALTER TABLE).

ALTER TABLE public.web_navigation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.navigation_category ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submit ENABLE ROW LEVEL SECURITY;

-- Public catalogue: read-only for the anon key used by the Next.js app.
DROP POLICY IF EXISTS "anon_read_web_navigation" ON public.web_navigation;
CREATE POLICY "anon_read_web_navigation" ON public.web_navigation
  FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_read_navigation_category" ON public.navigation_category;
CREATE POLICY "anon_read_navigation_category" ON public.navigation_category
  FOR SELECT TO anon, authenticated USING (true);

-- Community submissions: the /submit form and /api/submit insert with the anon key.
DROP POLICY IF EXISTS "anon_insert_submit" ON public.submit;
CREATE POLICY "anon_insert_submit" ON public.submit
  FOR INSERT TO anon, authenticated WITH CHECK (true);

-- NOTE: /api/cron and /api/cron_callback additionally need SELECT/UPDATE on submit
-- and SELECT/INSERT/UPDATE on web_navigation. Those are backend-only crawler flows:
-- grant them to a service_role key (or to anon only if you accept public writes).
