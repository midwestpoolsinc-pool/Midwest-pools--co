-- Customers may read only jobs explicitly linked to their account.
create policy jobs_customer_read
on public.jobs for select
to authenticated
using (private.customer_can_access_job(id));
