-- 2026-11-03 · 역할 4종, 일정 수정, 비밀번호 초기화, 평가기준표 사진
--
-- Roles
--   superadmin (최고관리자): everything, and the only one who can create/delete/reset 관리자
--   admin      (관리자)    : items, and create/delete/reset 반장·학생
--   monitor    (반장)      : items, and create 학생 / reset 학생 password (no delete)
--   student    (학생)      : view, done check, own password

-- ── roles ──────────────────────────────────────────────────────────────
alter table public.app_accounts drop constraint if exists app_accounts_role_check;
alter table public.app_accounts add constraint app_accounts_role_check
  check (role in ('superadmin', 'admin', 'monitor', 'student'));

update public.app_accounts set role = 'superadmin' where id = 'admin' and role = 'admin';

alter table public.app_items add column if not exists updated_at timestamptz;
alter table public.app_items add column if not exists updated_by text references public.app_accounts(id) on delete set null;
create index if not exists app_items_updated_by_idx on public.app_items(updated_by);

-- ── images (평가기준표) ─────────────────────────────────────────────────
create table if not exists public.app_images (
  id         bigint generated always as identity primary key,
  item_id    bigint not null references public.app_items(id) on delete cascade,
  data       text not null check (length(data) <= 1500000
                               and data ~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$'),
  created_by text references public.app_accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);
create index if not exists app_images_item_idx on public.app_images(item_id);
create index if not exists app_images_created_by_idx on public.app_images(created_by);
alter table public.app_images enable row level security;

-- ── helpers ────────────────────────────────────────────────────────────
create or replace function app_private.require_staff(p_token uuid)
returns public.app_accounts
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  if a.role not in ('superadmin', 'admin', 'monitor') then
    raise exception 'admin_only' using errcode = 'P0001';
  end if;
  return a;
end $$;

-- kept for compatibility: now means "staff"
create or replace function app_private.require_admin(p_token uuid)
returns public.app_accounts
language sql stable security definer set search_path = ''
as $$ select app_private.require_staff(p_token) $$;

-- may actor (role) do action ('create' | 'delete' | 'reset') to an account with target role?
create or replace function app_private.can_manage(p_actor text, p_action text, p_target text)
returns boolean
language sql immutable set search_path = ''
as $$
  select case p_actor
    when 'superadmin' then p_target in ('admin', 'monitor', 'student')
    when 'admin'      then p_target in ('monitor', 'student')
    when 'monitor'    then p_target = 'student' and p_action in ('create', 'reset')
    else false end
$$;

-- ── API ────────────────────────────────────────────────────────────────
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
             'date', to_char(i.date, 'YYYY-MM-DD'), 'desc', i.descr, 'detail', i.detail,
             'img', (select count(*) from public.app_images g where g.item_id = i.id and g.deleted_at is null))
             order by i.date, i.id)
      from public.app_items i where i.deleted_at is null), '[]'::json),
    'done', coalesce((
      select json_agg(d.item_id) from public.app_done d where d.account_id = a.id and d.done), '[]'::json),
    'accounts', case
      when a.role in ('superadmin', 'admin') then coalesce((
        select json_agg(json_build_object('id', x.id, 'name', x.name, 'role', x.role)
               order by case x.role when 'superadmin' then 0 when 'admin' then 1 when 'monitor' then 2 else 3 end, x.id)
        from public.app_accounts x where x.deleted_at is null), '[]'::json)
      when a.role = 'monitor' then coalesce((
        select json_agg(json_build_object('id', x.id, 'name', x.name, 'role', x.role) order by x.id)
        from public.app_accounts x where x.deleted_at is null and x.role = 'student'), '[]'::json)
      else '[]'::json end
  );
end $$;

create or replace function public.app_add_item(p_token uuid, p_subject text, p_title text, p_date date, p_desc text, p_detail text)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; new_id bigint;
begin
  a := app_private.require_staff(p_token);
  insert into public.app_items(subject, title, date, descr, detail, created_by)
  values (trim(p_subject), trim(p_title), p_date, coalesce(trim(p_desc), ''), coalesce(trim(p_detail), ''), a.id)
  returning id into new_id;
  return new_id;
end $$;

create or replace function public.app_update_item(p_token uuid, p_item_id bigint, p_subject text, p_title text, p_date date, p_desc text, p_detail text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.require_staff(p_token);
  update public.app_items
     set subject = trim(p_subject), title = trim(p_title), date = p_date,
         descr = coalesce(trim(p_desc), ''), detail = coalesce(trim(p_detail), ''),
         updated_at = now(), updated_by = a.id
   where id = p_item_id and deleted_at is null;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
end $$;

create or replace function public.app_delete_item(p_token uuid, p_item_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform app_private.require_staff(p_token);
  update public.app_items set deleted_at = now() where id = p_item_id and deleted_at is null;
end $$;

create or replace function public.app_item_images(p_token uuid, p_item_id bigint)
returns json
language plpgsql stable security definer set search_path = ''
as $$
begin
  perform app_private.session_user(p_token);
  return coalesce((
    select json_agg(json_build_object('id', g.id, 'data', g.data) order by g.id)
    from public.app_images g join public.app_items i on i.id = g.item_id
    where g.item_id = p_item_id and g.deleted_at is null and i.deleted_at is null), '[]'::json);
end $$;

create or replace function public.app_add_image(p_token uuid, p_item_id bigint, p_data text)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; new_id bigint;
begin
  a := app_private.require_staff(p_token);
  if not exists (select 1 from public.app_items where id = p_item_id and deleted_at is null) then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if (select count(*) from public.app_images where item_id = p_item_id and deleted_at is null) >= 5 then
    raise exception 'too_many_images' using errcode = 'P0001';
  end if;
  if p_data is null or length(p_data) > 1500000 then
    raise exception 'image_too_big' using errcode = 'P0001';
  end if;
  if p_data !~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$' then
    raise exception 'bad_image' using errcode = 'P0001';
  end if;
  insert into public.app_images(item_id, data, created_by) values (p_item_id, p_data, a.id)
  returning id into new_id;
  return new_id;
end $$;

create or replace function public.app_delete_image(p_token uuid, p_image_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform app_private.require_staff(p_token);
  update public.app_images set deleted_at = now() where id = p_image_id and deleted_at is null;
end $$;

create or replace function public.app_create_account(p_token uuid, p_id text, p_pw text, p_name text, p_role text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.require_staff(p_token);
  if not app_private.can_manage(a.role, 'create', p_role) then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
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
declare a public.app_accounts; t text;
begin
  a := app_private.require_staff(p_token);
  if a.id = p_id then
    raise exception 'cannot_delete_self' using errcode = 'P0001';
  end if;
  select role into t from public.app_accounts where id = p_id and deleted_at is null;
  if t is null then return; end if;
  if not app_private.can_manage(a.role, 'delete', t) then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  update public.app_accounts set deleted_at = now() where id = p_id and deleted_at is null;
  update public.app_sessions set expires_at = now() where account_id = p_id and expires_at > now();
end $$;

create or replace function public.app_reset_password(p_token uuid, p_id text, p_new text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; t text;
begin
  a := app_private.require_staff(p_token);
  select role into t from public.app_accounts where id = p_id and deleted_at is null;
  if t is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if a.id = p_id or not app_private.can_manage(a.role, 'reset', t) then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  if length(trim(coalesce(p_new, ''))) < 4 then
    raise exception 'pw_too_short' using errcode = 'P0001';
  end if;
  update public.app_accounts set pw_hash = extensions.crypt(trim(p_new), extensions.gen_salt('bf')) where id = p_id;
  update public.app_sessions set expires_at = now() where account_id = p_id and expires_at > now();
end $$;

-- only the page's functions are callable from the API
revoke all on function public.app_update_item(uuid, bigint, text, text, date, text, text) from public;
revoke all on function public.app_item_images(uuid, bigint) from public;
revoke all on function public.app_add_image(uuid, bigint, text) from public;
revoke all on function public.app_delete_image(uuid, bigint) from public;
revoke all on function public.app_reset_password(uuid, text, text) from public;
grant execute on function public.app_update_item(uuid, bigint, text, text, date, text, text) to anon, authenticated;
grant execute on function public.app_item_images(uuid, bigint) to anon, authenticated;
grant execute on function public.app_add_image(uuid, bigint, text) to anon, authenticated;
grant execute on function public.app_delete_image(uuid, bigint) to anon, authenticated;
grant execute on function public.app_reset_password(uuid, text, text) to anon, authenticated;
revoke all on function app_private.can_manage(text, text, text) from public;
revoke all on function app_private.require_staff(uuid) from public;
