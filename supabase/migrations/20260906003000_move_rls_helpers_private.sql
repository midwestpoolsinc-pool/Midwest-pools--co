-- Keep privileged lookups outside the exposed API schema.
create or replace function private.current_user_role()
returns public.user_role
language sql
stable
security definer
set search_path = ''
as $$
  select role from public.profiles where id = (select auth.uid()) and active = true;
$$;

create or replace function public.current_user_role()
returns public.user_role
language sql
stable
security invoker
set search_path = ''
as $$ select private.current_user_role(); $$;

create or replace function private.can_access_job(p_job_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id=(select auth.uid()) and p.active
      and p.role in ('super_admin'::public.user_role,'admin'::public.user_role,'office'::public.user_role)
  ) or exists (
    select 1 from public.jobs j
    where j.id=p_job_id and j.deleted_at is null and (
      j.project_manager_id=(select auth.uid()) or exists (
        select 1 from public.job_assignments a
        where a.job_id=j.id and a.user_id=(select auth.uid()) and a.active
      )
    )
  );
$$;

create or replace function public.can_access_job(p_job_id uuid)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$ select private.can_access_job(p_job_id); $$;

revoke all on function private.current_user_role() from public, anon;
revoke all on function private.can_access_job(uuid) from public, anon;
grant execute on function private.current_user_role() to authenticated;
grant execute on function private.can_access_job(uuid) to authenticated;
