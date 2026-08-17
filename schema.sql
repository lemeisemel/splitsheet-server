-- Run this once in Supabase's SQL editor to create the sessions table.

create table if not exists roblox_sessions (
  roblox_user_id text primary key,
  username text,
  access_token text not null,
  refresh_token text not null,
  expires_at timestamptz not null,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Row Level Security: only the server (using the service role key) can read/write.
alter table roblox_sessions enable row level security;

-- Single-row table holding the "owner-only" toggle, so it persists across
-- server restarts/redeploys instead of living in memory.
create table if not exists app_settings (
  id smallint primary key default 1,
  restrict_enabled boolean not null default false,
  updated_at timestamptz default now(),
  constraint single_row check (id = 1)
);
insert into app_settings (id, restrict_enabled) values (1, false) on conflict (id) do nothing;
alter table app_settings enable row level security;
