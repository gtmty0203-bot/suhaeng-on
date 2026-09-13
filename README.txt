수행ON Supabase 연결 버전

[현재 단계]
1. supabase-config.js를 열고 PASTE_YOUR_PUBLISHABLE_KEY_HERE를
   Supabase > Project Settings > API Keys > Publishable key 값으로 바꾸세요.
2. Supabase > Authentication > Users에서 관리자 계정을 만드세요.
   이메일과 비밀번호는 본인이 정합니다.
3. 이미 만든 public.assignments 테이블과 RLS 정책을 그대로 사용합니다.
4. GitHub에 demo8 폴더의 파일을 업로드하고 Vercel에서 배포합니다.

[중요]
- Publishable key는 브라우저에 사용하도록 공개 가능한 키입니다.
- sb_secret_ 또는 service_role 키는 절대 웹사이트 코드에 넣지 마세요.
- 기존 사이트의 localStorage 데이터가 있다면, 첫 관리자 로그인 때 DB가 비어 있을 경우 자동으로 DB에 한 번 이전하도록 해두었습니다.
