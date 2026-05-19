function copyText(id){const el=document.getElementById(id);const text=el?el.innerText:"";if(!text)return;navigator.clipboard.writeText(text).then(()=>alert("已复制"));}
