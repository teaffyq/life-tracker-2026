-- Life Tracker: lock the database to Tiffany and Nic.
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- Before running, replace the two emails in step 1 IN THE SQL EDITOR ONLY.
-- Don't commit real emails to this file; the repo may be public.

-- 1. Members: which signed-in email is Tiffany and which is Nic
create table if not exists public.members (
  email text primary key,
  role  text not null check (role in ('tiff', 'nic'))
);

insert into public.members (email, role) values
  ('TIFFANY_EMAIL_HERE', 'tiff'),
  ('NIC_EMAIL_HERE',     'nic')
on conflict (email) do update set role = excluded.role;

alter table public.members enable row level security;

drop policy if exists "read own membership" on public.members;
create policy "read own membership" on public.members
  for select to authenticated
  using (email = lower(auth.jwt() ->> 'email'));

-- 2. Helper: the signed-in user's role ('tiff', 'nic', or null)
create or replace function public.member_role()
returns text
language sql stable security definer
set search_path = public
as $$
  select role from public.members where email = lower(auth.jwt() ->> 'email');
$$;

-- Lane ownership, matching LANE_OWNER in index.html
create or replace function public.can_edit_lane(lane text)
returns boolean
language sql stable
set search_path = public
as $$
  select case
    when lane in ('wedding', 'reno')  then public.member_role() in ('tiff', 'nic')
    when lane in ('work', 'masters')  then public.member_role() = 'tiff'
    when lane = 'nic'                 then public.member_role() = 'nic'
    else false
  end;
$$;

-- 3. Tasks: remove every existing policy (including any open "anon" ones), then add strict ones
alter table public.tasks enable row level security;

do $$
declare p record;
begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'tasks' loop
    execute format('drop policy %I on public.tasks', p.policyname);
  end loop;
end $$;

create policy "members can read" on public.tasks
  for select to authenticated
  using (public.member_role() is not null);

create policy "owners can add" on public.tasks
  for insert to authenticated
  with check (public.can_edit_lane(lane));

create policy "owners can edit" on public.tasks
  for update to authenticated
  using (public.can_edit_lane(lane))
  with check (public.can_edit_lane(lane));

create policy "owners can delete" on public.tasks
  for delete to authenticated
  using (public.can_edit_lane(lane));

-- 4. Check: should return your two emails
select * from public.members;
