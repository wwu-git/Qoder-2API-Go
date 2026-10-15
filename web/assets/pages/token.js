/* ═══ 页面层：令牌（多账号池：权重、健康状态、验证） ═══ */
PAGE('token', {
  realtime: true,

  tokens: [], tokenTotal: 0, tokenAvailable: 0,
  tokenModal: false,
  tokenForm: {pat:'', note:'', weight:1},

  get tokenSummary(){
    if(!this.tokens.length) return '尚未配置账号';
    return `共 ${this.tokenTotal} 个账号 · ${this.tokenAvailable} 个可接流量`;
  },

  /* 服务端只回掩码形式；明文 PAT 只在提交时经过一次，从不就地改写（换令牌 = 删账号 + 加账号）。 */
  async loadTokens(){
    try{
      const r = await this.api('/admin/api/tokens');
      this.tokens = r.tokens || [];
      this.tokenTotal = r.total || 0;
      this.tokenAvailable = r.available || 0;
    }catch(e){ this.toast(e.message,'err'); }
  },

  openTokenModal(){
    this.tokenForm = {pat:'', note:'', weight:1};
    this.tokenModal = true;
  },

  async addToken(){
    const pat = (this.tokenForm.pat||'').trim();
    if(!pat){ this.toast('令牌不能为空','err'); return; }
    this.busy(async()=>{
      // 服务端先向网关校验，通过才落盘：坏令牌进池会白扣一次账号轮换。
      await this.api('/admin/api/tokens',{method:'POST',body:JSON.stringify({
        pat, note:(this.tokenForm.note||'').trim(), weight:this.tokenForm.weight||1 })});
      this.toast('账号已添加','ok');
      this.tokenModal = false;
      this.loadTokens();
    })();
  },

  async saveWeight(t){
    const w = Number(t.weight);
    if(!Number.isInteger(w) || w<1 || w>100){
      this.toast('权重需在 1-100 之间','err'); this.loadTokens(); return;
    }
    this.busy(async()=>{
      await this.api('/admin/api/tokens?id='+encodeURIComponent(t.id),{method:'PUT',body:JSON.stringify({weight:w})});
      this.toast('权重已更新','ok'); this.loadTokens();
    })();
  },

  /* 停用是操作员开关（配置层），与网关给出的健康判定是两回事，界面上分开呈现。 */
  async toggleToken(t){
    this.busy(async()=>{
      await this.api('/admin/api/tokens?id='+encodeURIComponent(t.id),{method:'PUT',body:JSON.stringify({disabled:!t.disabled})});
      this.toast(t.disabled?'账号已启用':'账号已停用，不再接新请求','ok');
      this.loadTokens();
    })();
  },

  /* 重新验证：凭证被网关拒过的账号，靠这个动作回到轮换，无需重填令牌。 */
  async verifyToken(t){
    this.busy(async()=>{
      const r = await this.api('/admin/api/tokens/verify?id='+encodeURIComponent(t.id),{method:'POST'});
      this.toast(r.tag || r.plan ? `校验通过（${r.tag||r.plan}）` : '校验通过','ok');
      this.loadTokens();
    })();
  },

  deleteToken(t){
    this.askConfirm('删除账号', `确定从池中删除「${t.note||t.pat_masked}」？此操作不可撤销。`, ()=>{
      this.busy(async()=>{
        await this.api('/admin/api/tokens?id='+encodeURIComponent(t.id),{method:'DELETE'});
        this.toast('账号已删除','ok'); this.loadTokens();
      })();
    });
  },

  tokenStateText(t){
    if(t.disabled) return '已停用';
    return ({healthy:'正常', cooldown:'冷却中', disabled:'凭证被拒'})[t.state] || t.state;
  },
  tokenStateKind(t){
    if(t.disabled) return 'badge-muted';
    return ({healthy:'badge-ok', cooldown:'badge-warn', disabled:'badge-err'})[t.state] || 'badge-muted';
  },
  /* 冷却中显示回池时间点：操作员关心的是「什么时候恢复」，而不是内部状态名。 */
  tokenStateHint(t){
    if(t.state==='cooldown' && t.cooldown_until_ms) return '至 '+this.ts(new Date(t.cooldown_until_ms));
    return t.reason || '';
  },

  /* ── 进场：本页所需数据（额度快照由服务端的账号循环每分钟更新，这里只读缓存） ── */
  load(){ this.loadTokens(); },
});
