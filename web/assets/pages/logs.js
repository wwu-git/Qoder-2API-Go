/* ═══ 页面层：日志（PAGE(key, def) 注册本页专属状态与动作） ═══ */
PAGE('logs', {
  realtime: true,

  /* ── 日志 ── */
  /* 模型筛选走防抖（模糊输入），密钥/状态筛选切换即查；密钥下拉复用 keys 页的 loadKeys。 */
  loadLogsDebounced(){
    clearTimeout(this._logT);
    this._logT = setTimeout(()=>this.loadLogs(1), 500);
  },
  async loadLogs(page){
    if(page<1) page = 1;
    const f = this.logFilter;
    const qs = new URLSearchParams({page, page_size:this.logPageSize});
    if(f.model) qs.set('model', f.model);
    if(f.key_id) qs.set('key_id', f.key_id);
    if(f.status) qs.set('status', f.status);
    try{
      const r = await this.api('/admin/api/logs?'+qs);
      this.logs = r.logs||[]; this.logTotal = r.total||0; this.logPage = r.page||page;
    }catch(e){ this.toast(e.message,'err'); }
  },

  /* 降级链路：一次请求 touched 多个账号时（首次尝试失败且响应还没发出），把每一次
     尝试摊开在鼠标悬停里——操作员需要知道额度是在几个账号上花掉的。 */
  attemptsTip(l){
    const a = l.attempts || [];
    if(a.length < 2) return '';
    return '账号轮换：' + a.map((x,i)=>{
      const name = x.note || x.token_id || '未知账号';
      return '#' + (i+1) + ' ' + name + ' ' + (x.ok ? '成功' : '失败：' + (x.error || '未知原因'));
    }).join(' → ');
  },

  /* ── 进场：本页所需数据（realtime：进入即刷新，见 app.js enter()） ── */
  load(){ this.loadKeys(); this.loadLogs(1); },
});
