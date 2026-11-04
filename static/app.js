document.getElementById('theme-toggle')?.addEventListener('click',()=>{
  const next=document.documentElement.dataset.theme==='dark'?'light':'dark';
  document.documentElement.dataset.theme=next;
  localStorage.setItem('theme',next);
});

window.initSiteForm=()=>{
  const auth=document.getElementById('auth-type');
  const password=document.getElementById('password-field');
  const key=document.getElementById('key-field');
  const updateAuth=()=>{
    const keyMode=auth.value==='key';
    password.style.display=keyMode?'none':'flex';
    key.style.display=keyMode?'flex':'none';
  };
  auth?.addEventListener('change',updateAuth); updateAuth();

  const editor=document.getElementById('script');
  document.querySelectorAll('[data-insert]').forEach(button=>button.addEventListener('click',()=>{
    const value=button.dataset.insert;
    const start=editor.selectionStart, end=editor.selectionEnd;
    editor.setRangeText(value,start,end,'end'); editor.focus();
  }));

  const select=document.getElementById('certificate-select');
  const help=document.getElementById('cert-path-help');
  const updateCert=()=>{
    const option=select.options[select.selectedIndex];
    help.textContent=option?.value
      ? `已选：${option.dataset.cert} / ${option.dataset.key}；脚本中使用 {{CERT_PEM}} / {{CERT_KEY}}`
      : '部署时将上传为 {{CERT_PEM}} 和 {{CERT_KEY}}';
  };
  select?.addEventListener('change',updateCert); updateCert();
};

window.initCronPreview=()=>{
  const input=document.getElementById('cron-input');
  const output=document.getElementById('cron-next');
  let timer;
  const update=()=>{
    clearTimeout(timer);
    timer=setTimeout(async()=>{
      const expression=input.value.trim();
      if(!expression){output.textContent='请输入 cron 表达式';return;}
      try{
        const response=await fetch(`/api/cron-next?cron=${encodeURIComponent(expression)}`);
        const data=await response.json();
        if(!response.ok) throw new Error(data.message);
        output.textContent=`下次执行：${data.next_run}（${data.timezone}）`;
        output.classList.remove('invalid');
      }catch(error){
        output.textContent=error.message||'cron 表达式无效';
        output.classList.add('invalid');
      }
    },250);
  };
  input?.addEventListener('input',update); update();
};
