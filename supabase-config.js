// Supabase 공개 클라이언트 설정
// 아래 Publishable key만 넣으세요. sb_secret_ / service_role 키는 절대 넣지 마세요.
window.SUPABASE_URL = 'https://facewpuuybgtagihporn.supabase.co';
window.SUPABASE_PUBLISHABLE_KEY = 'PASTE_YOUR_PUBLISHABLE_KEY_HERE';
window.supabaseClient = supabase.createClient(
  window.SUPABASE_URL,
  window.SUPABASE_PUBLISHABLE_KEY
);
