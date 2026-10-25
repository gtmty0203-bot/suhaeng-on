-- 수행평가 달력 · Supabase schema (applied 2026-10-25 to project facewpuuybgtagihporn)
--
-- How it works
-- * The page (index.html) only calls the public.app_* functions through /rest/v1/rpc
--   with the publishable key. Tables have RLS on and no policies, so the key cannot
--   read or write them directly.
-- * Login returns a session token (30 days). Every function checks that token;
--   admin-only functions also check the role.
-- * Passwords are stored as bcrypt hashes (pgcrypto).
-- * Removing an item or an account marks it with deleted_at instead of erasing it,
--   so a mistake can be undone from the Supabase table editor.

create extension if not exists pgcrypto with schema extensions;
create schema if not exists app_private;

create table if not exists public.app_accounts (
  id         text primary key check (length(trim(id)) between 1 and 40),
  pw_hash    text not null,
  name       text not null check (length(trim(name)) between 1 and 40),
  role       text not null check (role in ('admin', 'student')),
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table if not exists public.app_items (
  id         bigint generated always as identity primary key,
  subject    text not null check (length(trim(subject)) between 1 and 30),
  title      text not null check (length(trim(title)) between 1 and 100),
  date       date not null,
  descr      text not null default '' check (length(descr) <= 300),
  detail     text not null default '' check (length(detail) <= 5000),
  created_by text references public.app_accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);
create index if not exists app_items_date_idx on public.app_items(date);
create index if not exists app_items_created_by_idx on public.app_items(created_by);

create table if not exists public.app_done (
  account_id text   not null references public.app_accounts(id) on delete cascade,
  item_id    bigint not null references public.app_items(id) on delete cascade,
  created_at timestamptz not null default now(),
  done       boolean not null default true,
  primary key (account_id, item_id)
);
create index if not exists app_done_item_idx on public.app_done(item_id);

create table if not exists public.app_sessions (
  token      uuid primary key default gen_random_uuid(),
  account_id text not null references public.app_accounts(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 days'
);
create index if not exists app_sessions_account_idx on public.app_sessions(account_id);

alter table public.app_accounts enable row level security;
alter table public.app_items    enable row level security;
alter table public.app_done     enable row level security;
alter table public.app_sessions enable row level security;

-- ── internal helpers (app_private is not exposed by the API) ───────────
create or replace function app_private.session_user(p_token uuid)
returns public.app_accounts
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  select acc.* into a
  from public.app_sessions s join public.app_accounts acc on acc.id = s.account_id
  where s.token = p_token and s.expires_at > now() and acc.deleted_at is null;
  if a.id is null then
    raise exception 'session_expired' using errcode = 'P0001';
  end if;
  return a;
end $$;

create or replace function app_private.require_admin(p_token uuid)
returns public.app_accounts
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  if a.role <> 'admin' then
    raise exception 'admin_only' using errcode = 'P0001';
  end if;
  return a;
end $$;

-- ── API used by the page ───────────────────────────────────────────────
create or replace function public.app_login(p_id text, p_pw text)
returns json
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; t uuid;
begin
  select * into a from public.app_accounts where id = trim(p_id) and deleted_at is null;
  if a.id is null or a.pw_hash <> extensions.crypt(coalesce(p_pw, ''), a.pw_hash) then
    raise exception 'bad_login' using errcode = 'P0001';
  end if;
  insert into public.app_sessions(account_id) values (a.id) returning token into t;
  return json_build_object('token', t, 'user', json_build_object('id', a.id, 'name', a.name, 'role', a.role));
end $$;

create or replace function public.app_logout(p_token uuid)
returns void
language sql volatile security definer set search_path = ''
as $$ update public.app_sessions set expires_at = now() where token = p_token and expires_at > now() $$;

create or replace function public.app_state(p_token uuid)
returns json
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  return json_build_object(
    'user', json_build_object('id', a.id, 'name', a.name, 'role', a.role),
    'items', coalesce((
      select json_agg(json_build_object('id', i.id, 'subject', i.subject, 'title', i.title,
             'date', to_char(i.date, 'YYYY-MM-DD'), 'desc', i.descr, 'detail', i.detail)
             order by i.date, i.id)
      from public.app_items i where i.deleted_at is null), '[]'::json),
    'done', coalesce((
      select json_agg(d.item_id) from public.app_done d where d.account_id = a.id and d.done), '[]'::json),
    'accounts', case when a.role = 'admin' then coalesce((
      select json_agg(json_build_object('id', x.id, 'name', x.name, 'role', x.role) order by x.role, x.id)
      from public.app_accounts x where x.deleted_at is null), '[]'::json) else '[]'::json end
  );
end $$;

create or replace function public.app_set_done(p_token uuid, p_item_id bigint, p_done boolean)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  insert into public.app_done(account_id, item_id, done) values (a.id, p_item_id, p_done)
  on conflict (account_id, item_id) do update set done = excluded.done, created_at = now();
end $$;

create or replace function public.app_add_item(p_token uuid, p_subject text, p_title text, p_date date, p_desc text, p_detail text)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; new_id bigint;
begin
  a := app_private.require_admin(p_token);
  insert into public.app_items(subject, title, date, descr, detail, created_by)
  values (trim(p_subject), trim(p_title), p_date, coalesce(trim(p_desc), ''), coalesce(trim(p_detail), ''), a.id)
  returning id into new_id;
  return new_id;
end $$;

create or replace function public.app_delete_item(p_token uuid, p_item_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform app_private.require_admin(p_token);
  update public.app_items set deleted_at = now() where id = p_item_id and deleted_at is null;
end $$;

create or replace function public.app_create_account(p_token uuid, p_id text, p_pw text, p_name text, p_role text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform app_private.require_admin(p_token);
  if length(trim(coalesce(p_pw, ''))) < 4 then
    raise exception 'pw_too_short' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.app_accounts where id = trim(p_id) and deleted_at is null) then
    raise exception 'id_taken' using errcode = 'P0001';
  end if;
  insert into public.app_accounts(id, pw_hash, name, role)
  values (trim(p_id), extensions.crypt(trim(p_pw), extensions.gen_salt('bf')), trim(p_name), p_role)
  on conflict (id) do update set pw_hash = excluded.pw_hash, name = excluded.name, role = excluded.role,
                                 deleted_at = null, created_at = now();
  update public.app_done set done = false where account_id = trim(p_id) and done;
end $$;

create or replace function public.app_delete_account(p_token uuid, p_id text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.require_admin(p_token);
  if a.id = p_id then
    raise exception 'cannot_delete_self' using errcode = 'P0001';
  end if;
  update public.app_accounts set deleted_at = now() where id = p_id and deleted_at is null;
  update public.app_sessions set expires_at = now() where account_id = p_id and expires_at > now();
end $$;

create or replace function public.app_change_password(p_token uuid, p_old text, p_new text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  if a.pw_hash <> extensions.crypt(coalesce(p_old, ''), a.pw_hash) then
    raise exception 'bad_login' using errcode = 'P0001';
  end if;
  if length(trim(coalesce(p_new, ''))) < 4 then
    raise exception 'pw_too_short' using errcode = 'P0001';
  end if;
  update public.app_accounts set pw_hash = extensions.crypt(trim(p_new), extensions.gen_salt('bf')) where id = a.id;
end $$;

-- First admin (run once, then change the password from the page):
-- insert into public.app_accounts(id, pw_hash, name, role)
-- values ('admin', extensions.crypt('<temporary password>', extensions.gen_salt('bf')), '관리자', 'admin');
