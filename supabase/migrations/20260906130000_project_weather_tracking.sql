-- Current job-site weather location and historical weather snapshots.
alter table public.jobs
  add column if not exists weather_latitude double precision,
  add column if not exists weather_longitude double precision,
  add column if not exists weather_location_name text,
  add column if not exists weather_last_checked_at timestamptz;

create table if not exists public.job_weather_snapshots (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.jobs(id) on delete cascade,
  observed_at timestamptz not null,
  weather_code integer,
  temperature_f numeric(6,2),
  apparent_temperature_f numeric(6,2),
  precipitation_probability numeric(5,2),
  wind_speed_mph numeric(6,2),
  summary text,
  source text not null default 'Open-Meteo',
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now()
);

create index if not exists job_weather_snapshots_job_observed_idx
  on public.job_weather_snapshots (job_id, observed_at desc);

alter table public.job_weather_snapshots enable row level security;

drop policy if exists weather_snapshots_read_accessible on public.job_weather_snapshots;
create policy weather_snapshots_read_accessible
on public.job_weather_snapshots for select
to authenticated
using (
  public.can_access_job(job_id)
  or private.customer_can_access_job(job_id)
);

drop policy if exists weather_snapshots_staff_insert on public.job_weather_snapshots;
create policy weather_snapshots_staff_insert
on public.job_weather_snapshots for insert
to authenticated
with check (
  created_by = (select auth.uid())
  and public.can_access_job(job_id)
);

grant select, insert on public.job_weather_snapshots to authenticated;
