-- 2026-11-03 (2차) · 수행평가 예시 문항 (글 + 사진)
--
-- * app_items.examples   : 예시 문항 글 (최대 5000자)
-- * app_images.kind      : 'rubric' (평가기준표) | 'example' (예시 문항), 종류마다 일정당 5장까지
-- * app_state            : items에 examples, img(기준표 수), eximg(예시 사진 수), imgv(사진 변경 확인용) 추가
-- * app_add_item / app_update_item : p_examples 추가 (update에서 생략하면 기존 값 유지)
-- * app_add_image        : p_kind 추가 (생략하면 'rubric')
-- * app_item_images      : 각 사진의 kind도 돌려줌

alter table public.app_items add column if not exists examples text not null default ''
  check (length(examples) <= 5000);

alter table public.app_images add column if not exists kind text not null default 'rubric'
  check (kind in ('rubric', 'example'));

-- 시그니처가 바뀌는 함수는 지우고 다시 만든다 (같은 이름이 두 개 생기면 API가 헷갈림)
drop function if exists public.app_add_item(uuid, text, text, date, text, text);
drop function if exists public.app_update_item(uuid, bigint, text, text, date, text, text);
drop function if exists public.app_add_image(uuid, bigint, text);

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
             'examples', i.examples,
             'img', g.rubric_n, 'eximg', g.example_n, 'imgv', g.max_id)
             order by i.date, i.id)
      from public.app_items i
      cross join lateral (
        select count(*) filter (where x.kind = 'rubric')  as rubric_n,
               count(*) filter (where x.kind = 'example') as example_n,
               coalesce(max(x.id), 0)                     as max_id
        from public.app_images x where x.item_id = i.id and x.deleted_at is null) g
      where i.deleted_at is null), '[]'::json),
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

create function public.app_add_item(p_token uuid, p_subject text, p_title text, p_date date,
                                    p_desc text, p_detail text, p_examples text default null)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; new_id bigint;
begin
  a := app_private.require_staff(p_token);
  insert into public.app_items(subject, title, date, descr, detail, examples, created_by)
  values (trim(p_subject), trim(p_title), p_date, coalesce(trim(p_desc), ''), coalesce(trim(p_detail), ''),
          coalesce(trim(p_examples), ''), a.id)
  returning id into new_id;
  return new_id;
end $$;

create function public.app_update_item(p_token uuid, p_item_id bigint, p_subject text, p_title text, p_date date,
                                       p_desc text, p_detail text, p_examples text default null)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts;
begin
  a := app_private.require_staff(p_token);
  update public.app_items
     set subject = trim(p_subject), title = trim(p_title), date = p_date,
         descr = coalesce(trim(p_desc), ''), detail = coalesce(trim(p_detail), ''),
         examples = coalesce(trim(p_examples), examples),
         updated_at = now(), updated_by = a.id
   where id = p_item_id and deleted_at is null;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
end $$;

create or replace function public.app_item_images(p_token uuid, p_item_id bigint)
returns json
language plpgsql stable security definer set search_path = ''
as $$
begin
  perform app_private.session_user(p_token);
  return coalesce((
    select json_agg(json_build_object('id', g.id, 'data', g.data, 'kind', g.kind) order by g.id)
    from public.app_images g join public.app_items i on i.id = g.item_id
    where g.item_id = p_item_id and g.deleted_at is null and i.deleted_at is null), '[]'::json);
end $$;

create function public.app_add_image(p_token uuid, p_item_id bigint, p_data text, p_kind text default 'rubric')
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; new_id bigint; k text := coalesce(p_kind, 'rubric');
begin
  a := app_private.require_staff(p_token);
  if k not in ('rubric', 'example') then
    raise exception 'bad_image' using errcode = 'P0001';
  end if;
  if not exists (select 1 from public.app_items where id = p_item_id and deleted_at is null) then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
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

-- only the page's functions are callable from the API
revoke all on function public.app_add_item(uuid, text, text, date, text, text, text) from public;
revoke all on function public.app_update_item(uuid, bigint, text, text, date, text, text, text) from public;
revoke all on function public.app_add_image(uuid, bigint, text, text) from public;
grant execute on function public.app_add_item(uuid, text, text, date, text, text, text) to anon, authenticated;
grant execute on function public.app_update_item(uuid, bigint, text, text, date, text, text, text) to anon, authenticated;
grant execute on function public.app_add_image(uuid, bigint, text, text) to anon, authenticated;

notify pgrst, 'reload schema';
