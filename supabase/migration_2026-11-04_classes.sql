-- 2026-11-04 · 반 구분, 반 관리자, 공통 일정
--
-- Roles (4 → 3)
--   superadmin (최고관리자): every class, classes, 공통 일정, who is 반 관리자
--   manager    (반 관리자) : one per class; own class items, own class students (create/reset/delete)
--   student    (학생)      : own class items, done check, own password
--
-- app_items.class_id null  = 공통 일정 (only staff can see it; date may be empty)
-- app_items.source_id      = the 공통 일정 a class item was imported from

-- ── classes ────────────────────────────────────────────────────────────
create table if not exists public.app_classes (
  id         bigint generated always as identity primary key,
  name       text not null check (length(trim(name)) between 1 and 30),
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);
create unique index if not exists app_classes_name_uq on public.app_classes (lower(trim(name))) where deleted_at is null;
alter table public.app_classes enable row level security;

insert into public.app_classes(name)
select '1학년 10반' where not exists (select 1 from public.app_classes where deleted_at is null);

-- ── accounts ───────────────────────────────────────────────────────────
alter table public.app_accounts add column if not exists class_id bigint references public.app_classes(id);
create index if not exists app_accounts_class_idx on public.app_accounts(class_id);

alter table public.app_accounts drop constraint if exists app_accounts_role_check;
update public.app_accounts set role = 'manager' where role in ('admin', 'monitor');
alter table public.app_accounts add constraint app_accounts_role_check
  check (role in ('superadmin', 'manager', 'student'));

update public.app_accounts
   set class_id = (select min(id) from public.app_classes where deleted_at is null)
 where role <> 'superadmin' and class_id is null;

alter table public.app_accounts drop constraint if exists app_accounts_class_chk;
alter table public.app_accounts add constraint app_accounts_class_chk
  check (role = 'superadmin' or class_id is not null);

-- one 반 관리자 per class
create unique index if not exists app_accounts_one_manager
  on public.app_accounts(class_id) where role = 'manager' and deleted_at is null;

-- ── items ──────────────────────────────────────────────────────────────
alter table public.app_items add column if not exists class_id bigint references public.app_classes(id);
alter table public.app_items add column if not exists source_id bigint references public.app_items(id) on delete set null;
create index if not exists app_items_class_idx on public.app_items(class_id);
create index if not exists app_items_source_idx on public.app_items(source_id);

update public.app_items
   set class_id = (select min(id) from public.app_classes where deleted_at is null)
 where class_id is null;

alter table public.app_items alter column date drop not null;
alter table public.app_items drop constraint if exists app_items_date_chk;
alter table public.app_items add constraint app_items_date_chk check (class_id is null or date is not null);

-- ── helpers ────────────────────────────────────────────────────────────
create or replace function app_private.require_staff(p_token uuid)
returns public.app_accounts
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  if a.role not in ('superadmin', 'manager') then
    raise exception 'admin_only' using errcode = 'P0001';
  end if;
  return a;
end $$;

create or replace function app_private.require_super(p_token uuid)
returns public.app_accounts
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  if a.role <> 'superadmin' then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  return a;
end $$;

-- the class a staff member writes into: 최고관리자 must name a live class, 반 관리자 always gets their own
create or replace function app_private.target_class(a public.app_accounts, p_class_id bigint)
returns bigint
language plpgsql stable security definer set search_path = ''
as $$
begin
  if a.role = 'superadmin' then
    if p_class_id is null or not exists (select 1 from public.app_classes where id = p_class_id and deleted_at is null) then
      raise exception 'class_required' using errcode = 'P0001';
    end if;
    return p_class_id;
  end if;
  if a.role <> 'manager' then
    raise exception 'admin_only' using errcode = 'P0001';
  end if;
  if p_class_id is not null and p_class_id is distinct from a.class_id then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  return a.class_id;
end $$;

-- may this account read (p_write = false) or change (true) this item?
create or replace function app_private.item_access(a public.app_accounts, p_item_id bigint, p_write boolean)
returns public.app_items
language plpgsql stable security definer set search_path = ''
as $$
declare i public.app_items;
begin
  select * into i from public.app_items where id = p_item_id and deleted_at is null;
  if i.id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if a.role = 'superadmin' then return i; end if;
  if i.class_id is null then
    -- 공통 일정: 반 관리자 can read it (to import), only 최고관리자 can change it
    if a.role <> 'manager' then raise exception 'not_found' using errcode = 'P0001'; end if;
    if p_write then raise exception 'no_permission' using errcode = 'P0001'; end if;
    return i;
  end if;
  if i.class_id is distinct from a.class_id then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if p_write and a.role <> 'manager' then
    raise exception 'admin_only' using errcode = 'P0001';
  end if;
  return i;
end $$;

-- ── state ──────────────────────────────────────────────────────────────
drop function if exists public.app_state(uuid);
create function public.app_state(p_token uuid, p_class_id bigint default null)
returns json
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts; cid bigint; my_class text;
begin
  a := app_private.session_user(p_token);
  if a.role = 'superadmin' then
    select c.id into cid from public.app_classes c where c.id = p_class_id and c.deleted_at is null;
    if cid is null then
      select min(c.id) into cid from public.app_classes c where c.deleted_at is null;
    end if;
  else
    cid := a.class_id;
  end if;
  select c.name into my_class from public.app_classes c where c.id = a.class_id;
  return json_build_object(
    'user', json_build_object('id', a.id, 'name', a.name, 'role', a.role, 'class_id', a.class_id, 'class_name', my_class),
    'class_id', cid,
    'classes', coalesce((
      select json_agg(json_build_object('id', c.id, 'name', c.name,
               'students', (select count(*) from public.app_accounts x where x.class_id = c.id and x.deleted_at is null and x.role = 'student'),
               'manager', (select x.name from public.app_accounts x where x.class_id = c.id and x.deleted_at is null and x.role = 'manager' limit 1))
             order by c.id)
      from public.app_classes c
      where c.deleted_at is null and (a.role = 'superadmin' or c.id = a.class_id)), '[]'::json),
    'items', coalesce((
      select json_agg(json_build_object('id', i.id, 'subject', i.subject, 'title', i.title,
             'date', to_char(i.date, 'YYYY-MM-DD'), 'desc', i.descr, 'detail', i.detail,
             'examples', i.examples, 'source_id', i.source_id,
             'img', g.rubric_n, 'eximg', g.example_n, 'imgv', g.max_id)
             order by i.date, i.id)
      from public.app_items i
      cross join lateral (
        select count(*) filter (where x.kind = 'rubric')  as rubric_n,
               count(*) filter (where x.kind = 'example') as example_n,
               coalesce(max(x.id), 0)                     as max_id
        from public.app_images x where x.item_id = i.id and x.deleted_at is null) g
      where i.deleted_at is null and i.class_id = cid), '[]'::json),
    'commons', case when a.role in ('superadmin', 'manager') then coalesce((
      select json_agg(json_build_object('id', i.id, 'subject', i.subject, 'title', i.title,
             'date', to_char(i.date, 'YYYY-MM-DD'), 'desc', i.descr, 'detail', i.detail,
             'examples', i.examples, 'common', true,
             'imported', exists (select 1 from public.app_items y
                                 where y.source_id = i.id and y.class_id = cid and y.deleted_at is null),
             'img', g.rubric_n, 'eximg', g.example_n, 'imgv', g.max_id)
             order by i.id desc)
      from public.app_items i
      cross join lateral (
        select count(*) filter (where x.kind = 'rubric')  as rubric_n,
               count(*) filter (where x.kind = 'example') as example_n,
               coalesce(max(x.id), 0)                     as max_id
        from public.app_images x where x.item_id = i.id and x.deleted_at is null) g
      where i.deleted_at is null and i.class_id is null), '[]'::json)
      else '[]'::json end,
    'done', coalesce((
      select json_agg(d.item_id) from public.app_done d where d.account_id = a.id and d.done), '[]'::json),
    'accounts', case
      when a.role = 'superadmin' then coalesce((
        select json_agg(json_build_object('id', x.id, 'name', x.name, 'role', x.role, 'class_id', x.class_id)
               order by case x.role when 'manager' then 0 else 1 end, x.id)
        from public.app_accounts x where x.deleted_at is null and x.class_id = cid), '[]'::json)
      when a.role = 'manager' then coalesce((
        select json_agg(json_build_object('id', x.id, 'name', x.name, 'role', x.role, 'class_id', x.class_id) order by x.id)
        from public.app_accounts x where x.deleted_at is null and x.role = 'student' and x.class_id = a.class_id), '[]'::json)
      else '[]'::json end
  );
end $$;

-- ── items ──────────────────────────────────────────────────────────────
drop function if exists public.app_add_item(uuid, text, text, date, text, text, text);
create function public.app_add_item(p_token uuid, p_subject text, p_title text, p_date date, p_desc text, p_detail text,
                                    p_examples text default null, p_class_id bigint default null, p_common boolean default false)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; cid bigint; new_id bigint;
begin
  a := app_private.require_staff(p_token);
  if coalesce(p_common, false) then
    if a.role <> 'superadmin' then
      raise exception 'no_permission' using errcode = 'P0001';
    end if;
    cid := null;
  else
    cid := app_private.target_class(a, p_class_id);
    if p_date is null then
      raise exception 'date_required' using errcode = 'P0001';
    end if;
  end if;
  insert into public.app_items(subject, title, date, descr, detail, examples, created_by, class_id)
  values (trim(p_subject), trim(p_title), p_date, coalesce(trim(p_desc), ''), coalesce(trim(p_detail), ''),
          coalesce(trim(p_examples), ''), a.id, cid)
  returning id into new_id;
  return new_id;
end $$;

create or replace function public.app_update_item(p_token uuid, p_item_id bigint, p_subject text, p_title text, p_date date,
                                                  p_desc text, p_detail text, p_examples text default null)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; i public.app_items;
begin
  a := app_private.require_staff(p_token);
  i := app_private.item_access(a, p_item_id, true);
  if i.class_id is not null and p_date is null then
    raise exception 'date_required' using errcode = 'P0001';
  end if;
  update public.app_items
     set subject = trim(p_subject), title = trim(p_title), date = p_date,
         descr = coalesce(trim(p_desc), ''), detail = coalesce(trim(p_detail), ''),
         examples = coalesce(trim(p_examples), examples),
         updated_at = now(), updated_by = a.id
   where id = p_item_id and deleted_at is null;
end $$;

create or replace function public.app_delete_item(p_token uuid, p_item_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.require_staff(p_token);
  perform app_private.item_access(a, p_item_id, true);
  update public.app_items set deleted_at = now() where id = p_item_id and deleted_at is null;
end $$;

-- 공통 일정 → 우리 반 (with the changes the 반 관리자 made in the form; copies the photos they kept)
create function public.app_import_common(p_token uuid, p_common_id bigint, p_subject text, p_title text, p_date date,
                                         p_desc text, p_detail text, p_examples text default null,
                                         p_class_id bigint default null, p_skip_images bigint[] default null)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; cid bigint; src public.app_items; new_id bigint;
begin
  a := app_private.require_staff(p_token);
  cid := app_private.target_class(a, p_class_id);
  select * into src from public.app_items where id = p_common_id and class_id is null and deleted_at is null;
  if src.id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if p_date is null then
    raise exception 'date_required' using errcode = 'P0001';
  end if;
  insert into public.app_items(subject, title, date, descr, detail, examples, created_by, class_id, source_id)
  values (trim(p_subject), trim(p_title), p_date, coalesce(trim(p_desc), ''), coalesce(trim(p_detail), ''),
          coalesce(trim(p_examples), ''), a.id, cid, src.id)
  returning id into new_id;
  insert into public.app_images(item_id, data, kind, created_by)
  select new_id, g.data, g.kind, a.id
    from public.app_images g
   where g.item_id = src.id and g.deleted_at is null
     and not (g.id = any (coalesce(p_skip_images, '{}'::bigint[])))
   order by g.id;
  return new_id;
end $$;

create or replace function public.app_set_done(p_token uuid, p_item_id bigint, p_done boolean)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; i public.app_items;
begin
  a := app_private.session_user(p_token);
  i := app_private.item_access(a, p_item_id, false);
  if i.class_id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  insert into public.app_done(account_id, item_id, done) values (a.id, p_item_id, p_done)
  on conflict (account_id, item_id) do update set done = excluded.done, created_at = now();
end $$;

-- ── images ─────────────────────────────────────────────────────────────
create or replace function public.app_item_images(p_token uuid, p_item_id bigint)
returns json
language plpgsql stable security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.session_user(p_token);
  perform app_private.item_access(a, p_item_id, false);
  return coalesce((
    select json_agg(json_build_object('id', g.id, 'data', g.data, 'kind', g.kind) order by g.id)
    from public.app_images g
    where g.item_id = p_item_id and g.deleted_at is null), '[]'::json);
end $$;

create or replace function public.app_add_image(p_token uuid, p_item_id bigint, p_data text, p_kind text default 'rubric')
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; new_id bigint; k text := coalesce(p_kind, 'rubric');
begin
  a := app_private.require_staff(p_token);
  if k not in ('rubric', 'example') then
    raise exception 'bad_image' using errcode = 'P0001';
  end if;
  perform app_private.item_access(a, p_item_id, true);
  if (select count(*) from public.app_images where item_id = p_item_id and kind = k and deleted_at is null) >= 5 then
    raise exception 'too_many_images' using errcode = 'P0001';
  end if;
  if p_data is null or length(p_data) > 1500000 then
    raise exception 'image_too_big' using errcode = 'P0001';
  end if;
  if p_data !~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$' then
    raise exception 'bad_image' using errcode = 'P0001';
  end if;
  insert into public.app_images(item_id, data, kind, created_by) values (p_item_id, p_data, k, a.id)
  returning id into new_id;
  return new_id;
end $$;

create or replace function public.app_delete_image(p_token uuid, p_image_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; iid bigint;
begin
  a := app_private.require_staff(p_token);
  select item_id into iid from public.app_images where id = p_image_id and deleted_at is null;
  if iid is null then return; end if;
  perform app_private.item_access(a, iid, true);
  update public.app_images set deleted_at = now() where id = p_image_id and deleted_at is null;
end $$;

-- ── accounts ───────────────────────────────────────────────────────────
drop function if exists public.app_create_account(uuid, text, text, text, text);
create function public.app_create_account(p_token uuid, p_id text, p_pw text, p_name text, p_role text, p_class_id bigint default null)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; r text := coalesce(p_role, 'student'); cid bigint;
begin
  a := app_private.require_staff(p_token);
  if r not in ('student', 'manager') or (r = 'manager' and a.role <> 'superadmin') then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  cid := app_private.target_class(a, p_class_id);
  if length(trim(coalesce(p_pw, ''))) < 4 then
    raise exception 'pw_too_short' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.app_accounts where id = trim(p_id) and deleted_at is null) then
    raise exception 'id_taken' using errcode = 'P0001';
  end if;
  if r = 'manager' then
    -- one 반 관리자 per class: the old one goes back to being a 학생
    update public.app_accounts set role = 'student' where class_id = cid and role = 'manager' and deleted_at is null;
  end if;
  insert into public.app_accounts(id, pw_hash, name, role, class_id)
  values (trim(p_id), extensions.crypt(trim(p_pw), extensions.gen_salt('bf')), trim(p_name), r, cid)
  on conflict (id) do update set pw_hash = excluded.pw_hash, name = excluded.name, role = excluded.role,
                                 class_id = excluded.class_id, deleted_at = null, created_at = now();
  update public.app_done set done = false where account_id = trim(p_id) and done;
end $$;

-- 반 관리자 may only touch 학생 in their own class; 최고관리자 anyone but 최고관리자
create or replace function app_private.can_touch(a public.app_accounts, t public.app_accounts)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select t.id is not null and t.role <> 'superadmin' and a.id <> t.id and (
    a.role = 'superadmin'
    or (a.role = 'manager' and t.role = 'student' and t.class_id = a.class_id))
$$;

create or replace function public.app_delete_account(p_token uuid, p_id text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; t public.app_accounts;
begin
  a := app_private.require_staff(p_token);
  if a.id = p_id then
    raise exception 'cannot_delete_self' using errcode = 'P0001';
  end if;
  select * into t from public.app_accounts where id = p_id and deleted_at is null;
  if t.id is null then return; end if;
  if not app_private.can_touch(a, t) then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  update public.app_accounts set deleted_at = now() where id = p_id and deleted_at is null;
  update public.app_sessions set expires_at = now() where account_id = p_id and expires_at > now();
end $$;

create or replace function public.app_reset_password(p_token uuid, p_id text, p_new text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; t public.app_accounts;
begin
  a := app_private.require_staff(p_token);
  select * into t from public.app_accounts where id = p_id and deleted_at is null;
  if t.id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if not app_private.can_touch(a, t) then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  if length(trim(coalesce(p_new, ''))) < 4 then
    raise exception 'pw_too_short' using errcode = 'P0001';
  end if;
  update public.app_accounts set pw_hash = extensions.crypt(trim(p_new), extensions.gen_salt('bf')) where id = p_id;
  update public.app_sessions set expires_at = now() where account_id = p_id and expires_at > now();
end $$;

-- 최고관리자: 학생 ↔ 반 관리자 (keeps the account and its 준비 체크)
create function public.app_set_role(p_token uuid, p_id text, p_role text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; t public.app_accounts;
begin
  a := app_private.require_super(p_token);
  select * into t from public.app_accounts where id = p_id and deleted_at is null;
  if t.id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if t.role = 'superadmin' or p_role not in ('student', 'manager') then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  if p_role = 'manager' then
    update public.app_accounts set role = 'student'
     where class_id = t.class_id and role = 'manager' and deleted_at is null and id <> t.id;
  end if;
  update public.app_accounts set role = p_role where id = t.id;
end $$;

-- 최고관리자: move an account to another class (a 반 관리자 who moves becomes a 학생 there)
create function public.app_move_account(p_token uuid, p_id text, p_class_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; t public.app_accounts;
begin
  a := app_private.require_super(p_token);
  select * into t from public.app_accounts where id = p_id and deleted_at is null;
  if t.id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if t.role = 'superadmin' then
    raise exception 'no_permission' using errcode = 'P0001';
  end if;
  if not exists (select 1 from public.app_classes where id = p_class_id and deleted_at is null) then
    raise exception 'class_required' using errcode = 'P0001';
  end if;
  if t.class_id = p_class_id then return; end if;
  update public.app_accounts set class_id = p_class_id, role = 'student' where id = t.id;
end $$;

-- ── classes API (최고관리자) ───────────────────────────────────────────
create function public.app_add_class(p_token uuid, p_name text)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; n text := trim(coalesce(p_name, '')); new_id bigint;
begin
  a := app_private.require_super(p_token);
  if length(n) < 1 or length(n) > 30 then
    raise exception 'bad_class' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.app_classes where lower(trim(name)) = lower(n) and deleted_at is null) then
    raise exception 'class_name_taken' using errcode = 'P0001';
  end if;
  insert into public.app_classes(name) values (n) returning id into new_id;
  return new_id;
end $$;

create function public.app_rename_class(p_token uuid, p_class_id bigint, p_name text)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; n text := trim(coalesce(p_name, ''));
begin
  a := app_private.require_super(p_token);
  if length(n) < 1 or length(n) > 30 then
    raise exception 'bad_class' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.app_classes where lower(trim(name)) = lower(n) and deleted_at is null and id <> p_class_id) then
    raise exception 'class_name_taken' using errcode = 'P0001';
  end if;
  update public.app_classes set name = n where id = p_class_id and deleted_at is null;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
end $$;

create function public.app_delete_class(p_token uuid, p_class_id bigint)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.require_super(p_token);
  if exists (select 1 from public.app_accounts where class_id = p_class_id and deleted_at is null) then
    raise exception 'class_not_empty' using errcode = 'P0001';
  end if;
  update public.app_classes set deleted_at = now() where id = p_class_id and deleted_at is null;
end $$;

drop function if exists app_private.can_manage(text, text, text);

-- ── only the page's functions are callable from the API ────────────────
revoke all on function public.app_state(uuid, bigint) from public;
revoke all on function public.app_add_item(uuid, text, text, date, text, text, text, bigint, boolean) from public;
revoke all on function public.app_import_common(uuid, bigint, text, text, date, text, text, text, bigint, bigint[]) from public;
revoke all on function public.app_create_account(uuid, text, text, text, text, bigint) from public;
revoke all on function public.app_set_role(uuid, text, text) from public;
revoke all on function public.app_move_account(uuid, text, bigint) from public;
revoke all on function public.app_add_class(uuid, text) from public;
revoke all on function public.app_rename_class(uuid, bigint, text) from public;
revoke all on function public.app_delete_class(uuid, bigint) from public;
grant execute on function public.app_state(uuid, bigint) to anon, authenticated;
grant execute on function public.app_add_item(uuid, text, text, date, text, text, text, bigint, boolean) to anon, authenticated;
grant execute on function public.app_import_common(uuid, bigint, text, text, date, text, text, text, bigint, bigint[]) to anon, authenticated;
grant execute on function public.app_create_account(uuid, text, text, text, text, bigint) to anon, authenticated;
grant execute on function public.app_set_role(uuid, text, text) to anon, authenticated;
grant execute on function public.app_move_account(uuid, text, bigint) to anon, authenticated;
grant execute on function public.app_add_class(uuid, text) to anon, authenticated;
grant execute on function public.app_rename_class(uuid, bigint, text) to anon, authenticated;
grant execute on function public.app_delete_class(uuid, bigint) to anon, authenticated;
revoke all on function app_private.require_super(uuid) from public, anon, authenticated;
revoke all on function app_private.target_class(public.app_accounts, bigint) from public, anon, authenticated;
revoke all on function app_private.item_access(public.app_accounts, bigint, boolean) from public, anon, authenticated;
revoke all on function app_private.can_touch(public.app_accounts, public.app_accounts) from public, anon, authenticated;
