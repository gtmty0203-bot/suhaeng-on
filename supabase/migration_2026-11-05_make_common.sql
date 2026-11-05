-- 2026-11-05 · 반 일정을 공통 일정으로 바꾸기 (최고관리자만)
--
-- app_make_common(token, item_id)
--   * 최고관리자만 쓸 수 있다
--   * 반 일정(class_id 있음)을 복사해서 공통 일정(class_id null)을 새로 만든다. 사진도 같이 복사
--   * 날짜는 반마다 다르니 비워서 올린다(날짜 미정). 원래 반 일정의 날짜는 그대로
--   * 원래 반 일정은 지우지 않는다 (그 반 학생들의 준비 체크 기록이 그대로 남도록)
--   * 원래 반 일정의 source_id를 새 공통 일정으로 바꿔, 그 반에는 "✓ 가져옴"으로 보인다
--   * 새 공통 일정 id를 돌려준다

create or replace function public.app_make_common(p_token uuid, p_item_id bigint)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare a public.app_accounts; src public.app_items; new_id bigint;
begin
  a := app_private.require_super(p_token);
  select * into src from public.app_items where id = p_item_id and deleted_at is null;
  if src.id is null then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  if src.class_id is null then
    raise exception 'already_common' using errcode = 'P0001';
  end if;
  insert into public.app_items(subject, title, date, descr, detail, examples, created_by, class_id, source_id)
  values (src.subject, src.title, null, src.descr, src.detail, coalesce(src.examples, ''), a.id, null, null)
  returning id into new_id;
  insert into public.app_images(item_id, data, kind, created_by)
  select new_id, g.data, g.kind, a.id
    from public.app_images g
   where g.item_id = src.id and g.deleted_at is null
   order by g.id;
  update public.app_items set source_id = new_id where id = src.id;
  return new_id;
end $$;

revoke all on function public.app_make_common(uuid, bigint) from public;
grant execute on function public.app_make_common(uuid, bigint) to anon, authenticated;
