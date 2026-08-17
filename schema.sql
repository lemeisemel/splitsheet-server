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
