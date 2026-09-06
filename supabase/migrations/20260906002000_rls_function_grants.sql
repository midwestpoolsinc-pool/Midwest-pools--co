-- RLS helper functions must be executable by authenticated requests.
revoke all on function public.can_access_job(uuid) from public, anon;
revoke all on function public.current_user_role() from public, anon;
revoke all on function public.is_admin_or_office() from public, anon;
revoke all on function public.is_super_administrator() from public, anon;
grant execute on function public.can_access_job(uuid) to authenticated;
grant execute on function public.current_user_role() to authenticated;
grant execute on function public.is_admin_or_office() to authenticated;
grant execute on function public.is_super_administrator() to authenticated;

grant usage on schema private to authenticated;
revoke all on function private.customer_can_access_job(uuid) from public, anon;
revoke all on function private.finance_staff_can_access_job(uuid) from public, anon;
grant execute on function private.customer_can_access_job(uuid) to authenticated;
grant execute on function private.finance_staff_can_access_job(uuid) to authenticated;
