-- Midwest Pools OS production authorization and Trash hardening.
-- This migration tightens the existing RLS model; it does not grant anonymous access.

create or replace function private.is_super_administrator()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles p
    join auth.users u on u.id = p.id
    where p.id = (select auth.uid())
      and p.active = true
      and p.role = 'super_admin'::public.user_role
      and lower(coalesce(u.email, '')) = 'midwestpoolsinc@gmail.com'
  );
$$;

create or replace function public.is_super_administrator()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$ select private.is_super_administrator(); $$;

create or replace function private.guard_super_admin_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  target_email text;
begin
  select lower(email) into target_email
  from auth.users
  where id = coalesce(new.id, old.id);

  if tg_op = 'DELETE' and old.role = 'super_admin'::public.user_role then
    raise exception 'The Super Administrator profile cannot be deleted.';
  end if;

  if tg_op <> 'DELETE' then
    if new.role = 'super_admin'::public.user_role
       and target_email <> 'midwestpoolsinc@gmail.com' then
      raise exception 'Only midwestpoolsinc@gmail.com may be the Super Administrator.';
    end if;
    if old.role = 'super_admin'::public.user_role
       and (new.role <> 'super_admin'::public.user_role or not new.active) then
      raise exception 'The Super Administrator cannot be demoted or disabled.';
    end if;
  end if;

  return case when tg_op = 'DELETE' then old else new end;
end;
$$;

drop trigger if exists protect_super_admin_profile on public.profiles;
drop trigger if exists guard_super_admin_profile on public.profiles;
create trigger guard_super_admin_profile
before update or delete on public.profiles
for each row execute function private.guard_super_admin_profile();

-- Customers must never see company pool inventory or its financial columns.
drop policy if exists pool_inventory_read_authenticated on public.pool_inventory;
create policy pool_inventory_staff_read
on public.pool_inventory for select
to authenticated
using (
  deleted_at is null
  and public.current_user_role() in (
    'super_admin'::public.user_role,
    'admin'::public.user_role,
    'office'::public.user_role,
    'pm'::public.user_role,
    'employee'::public.user_role
  )
);

create or replace function public.move_to_trash(p_table text, p_id uuid)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if not public.is_admin_or_office() then raise exception 'Insufficient permission'; end if;
  if p_table not in (
    'jobs','pool_inventory','change_orders','invoices','payments','warranties',
    'job_tasks','job_notes','warranty_claims','warranty_documents','portal_documents'
  ) then raise exception 'Unsupported Trash record type'; end if;
  execute format(
    'update public.%I set deleted_at=now(), deleted_by=$1 where id=$2 and deleted_at is null',
    p_table
  ) using (select auth.uid()), p_id;
end;
$$;

create or replace function public.restore_from_trash(p_table text, p_id uuid)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if not public.is_admin_or_office() then raise exception 'Insufficient permission'; end if;
  if p_table not in (
    'jobs','pool_inventory','change_orders','invoices','payments','warranties',
    'job_tasks','job_notes','warranty_claims','warranty_documents','portal_documents'
  ) then raise exception 'Unsupported Trash record type'; end if;
  execute format(
    'update public.%I set deleted_at=null, deleted_by=null where id=$1 and deleted_at is not null',
    p_table
  ) using p_id;
end;
$$;

create or replace function public.permanently_delete_from_trash(p_table text, p_id uuid)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if not public.is_super_administrator() then
    raise exception 'Only the Super Administrator may permanently delete';
  end if;
  if p_table not in (
    'jobs','pool_inventory','change_orders','invoices','payments','warranties',
    'job_tasks','job_notes','warranty_claims','warranty_documents','portal_documents'
  ) then raise exception 'Unsupported Trash record type'; end if;
  execute format(
    'delete from public.%I where id=$1 and deleted_at is not null',
    p_table
  ) using p_id;
end;
$$;

revoke all on function public.move_to_trash(text, uuid) from public, anon;
revoke all on function public.restore_from_trash(text, uuid) from public, anon;
revoke all on function public.permanently_delete_from_trash(text, uuid) from public, anon;
grant execute on function public.move_to_trash(text, uuid) to authenticated;
grant execute on function public.restore_from_trash(text, uuid) to authenticated;
grant execute on function public.permanently_delete_from_trash(text, uuid) to authenticated;

-- Backfill the protected owner profile if that Auth account already exists.
insert into public.profiles (id, full_name, role, active)
select id, coalesce(raw_user_meta_data->>'full_name', split_part(email, '@', 1)),
       'super_admin'::public.user_role, true
from auth.users
where lower(email) = 'midwestpoolsinc@gmail.com'
on conflict (id) do update
set role = 'super_admin'::public.user_role, active = true, updated_at = now();
