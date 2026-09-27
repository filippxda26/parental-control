const $=(selector,root=document)=>root.querySelector(selector);
const devices=$('#devices'),dialog=$('#editor'),form=$('#form');
let socket=null,socketPromise=null,socketSeq=1,reconnectTimer=null,editing=null,latest=[];

function socketUrl(){
  return `${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws`;
}

function scheduleReconnect(){
  clearTimeout(reconnectTimer);
  if(document.visibilityState!=='visible')return;
  reconnectTimer=setTimeout(()=>connectSocket().catch(()=>{}),1000);
}

function connectSocket(){
  if(socket?.readyState===WebSocket.OPEN)return Promise.resolve(socket);
  if(socketPromise)return socketPromise;
  socketPromise=new Promise((resolve,reject)=>{
    const ws=new WebSocket(socketUrl());
    let opened=false,settled=false;
    socket=ws;
    const fail=message=>{
      if(settled)return;
      settled=true;
      socketPromise=null;
      reject(Error(message));
    };
    const timeout=setTimeout(()=>{
      if(ws.readyState!==WebSocket.OPEN){
        fail('Не удалось подключить WebSocket');
        try{ws.close()}catch{}
      }
    },5000);
    ws.onopen=()=>{
      opened=true;
      if(!settled){settled=true;resolve(ws)}
      clearTimeout(timeout);
      clearTimeout(reconnectTimer);
      socketPromise=null;
      $('#service').textContent='Служба работает';
    };
    ws.onmessage=event=>{
      let message;
      try{message=JSON.parse(event.data)}catch{return}
      if(message.type==='state'&&message.data){
        renderState(message.data);
        return;
      }
      if(message.type!=='response')return;
      const pending=socketPending.get(message.id);
      if(!pending)return;
      socketPending.delete(message.id);
      clearTimeout(pending.timer);
      const data=message.data||{};
      if(Number(message.status)>=400||data.success===false){
        pending.reject(Error(data.message||'Служба временно недоступна'));
      }else{
        pending.resolve(data);
      }
    };
    ws.onerror=()=>{};
    ws.onclose=()=>{
      clearTimeout(timeout);
      if(!opened)fail('WebSocket закрылся до подключения');
      else socketPromise=null;
      if(socket===ws)socket=null;
      for(const pending of socketPending.values()){
        clearTimeout(pending.timer);
        pending.reject(Error('WebSocket отключён'));
      }
      socketPending.clear();
      $('#service').textContent='Служба недоступна';
      scheduleReconnect();
    };
  });
  return socketPromise;
}

const socketPending=new Map();

async function api(path,options={}){
  const ws=await connectSocket(),id=socketSeq++;
  let body;
  if(options.body!==undefined&&options.body!==''){
    try{body=typeof options.body==='string'?JSON.parse(options.body):options.body}
    catch{body=options.body}
  }
  const message={id,method:options.method||'GET',path};
  if(body!==undefined)message.body=body;
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{
      socketPending.delete(id);
      reject(Error('Тайм-аут WebSocket'));
    },15000);
    socketPending.set(id,{resolve,reject,timer});
    try{ws.send(JSON.stringify(message))}
    catch(error){
      clearTimeout(timer);
      socketPending.delete(id);
      reject(error);
    }
  });
}

function duration(value){
  const seconds=Math.max(0,Math.floor(Number(value)||0));
  const minutes=Math.floor(seconds/60),rest=seconds%60;
  return rest?`${minutes} мин. ${rest} с.`:`${minutes} мин.`;
}

function reasonLabels(device){
  const active=new Set(device.block_reasons||[]),reasons=[];
  if(active.has('manual'))reasons.push('заблокировано вручную');
  if(active.has('night'))reasons.push('ночная блокировка');
  if(active.has('break'))reasons.push('отдых');
  if(active.has('daily_limit'))reasons.push('ограничение времени на день');
  if(active.has('whitelist'))reasons.push('режим Whitelist');
  return reasons;
}

function hasNight(device){
  return (device.block_reasons||[]).includes('night');
}

function deviceUiSignature(device){
  return JSON.stringify({
    id:device.id,
    name:device.name,
    hostname:device.hostname||'',
    hostnames:device.hostnames||[],
    mac:device.mac,
    macs:device.macs||[],
    ips:device.ips||[],
    linked_devices:device.linked_devices||[],
    mac_auto:!!device.mac_auto,
    ip:device.ip||'',
    enabled:device.enabled!==false,
    blocked:!!device.blocked,
    block_reason:device.block_reason||'',
    block_reasons:device.block_reasons||[],
    manual_blocked:!!device.manual_blocked,
    temporary_unblock:!!device.temporary_unblock,
    break_active:!!device.break_active,
    daily_limit_enabled:!!device.daily_limit_enabled,
    daily_limit_minutes:Number(device.daily_limit_minutes)||0,
    session_limit_enabled:!!device.session_limit_enabled,
    session_limit_minutes:Number(device.session_limit_minutes)||0,
    break_enabled:!!device.break_enabled,
    break_minutes:Number(device.break_minutes)||0,
    night_enabled:!!device.night_enabled,
    speed_limit_enabled:!!device.speed_limit_enabled,
    speed_limit_mbps:Number(device.speed_limit_mbps)||0,
    whitelist_enabled:!!device.whitelist_enabled,
    whitelist_active:!!device.whitelist_active,
    whitelist_enforced:!!device.whitelist_enforced,
    whitelist_start:device.whitelist_start||'',
    whitelist_end:device.whitelist_end||'',
    whitelist_entries:device.whitelist_entries||[],
    traffic_idle:!!device.traffic_idle,
    night_start:device.night_start||'',
    night_end:device.night_end||''
  });
}

function usageLine(className,text=''){
  const p=document.createElement('p');
  p.className=`usage ${className}`;
  p.textContent=text;
  return p;
}

function card(device){
  const article=$('#card').content.firstElementChild.cloneNode(true);
  article.dataset.id=device.id;
  const enabled=device.enabled!==false;
  const blocked=!!device.blocked;
  const night=hasNight(device);
  const manual=!!device.manual_blocked;
  const temporary=!!device.temporary_unblock;
  const cycle=!!device.session_limit_enabled&&!!device.break_enabled;

  $('.dot',article).classList.toggle('offline',!device.ip);
  $('h3',article).textContent=device.name||'Без имени';
  const linked=device.linked_devices||[];
  const deviceCount=linked.length;
  const countWord=(()=>{
    const n=deviceCount%100,m=n%10;
    if(n>=11&&n<=14)return 'подключённых устройств';
    if(m===1)return 'подключённое устройство';
    if(m>=2&&m<=4)return 'подключённых устройства';
    return 'подключённых устройств';
  })();
  $('.host',article).textContent=deviceCount?`${deviceCount} ${countWord}`:'';
  $('.host',article).hidden=!deviceCount;

  const dl=article.querySelector('dl');
  const ipRow=$('.ip',article).closest('div');
  const macRow=$('.mac',article).closest('div');

  if(linked.length){
    ipRow.style.display='none';
    macRow.style.display='none';

    const list=document.createElement('div');
    list.className='card-linked-devices';
    list.style.cssText='display:grid;gap:10px;margin:14px 0';

    linked.forEach((item,index)=>{
      const box=document.createElement('div');
      box.style.cssText='display:grid;gap:3px;padding-top:8px;border-top:1px solid rgba(127,127,127,.22)';

      const title=document.createElement('strong');
      title.textContent=item.hostname?`${index+1}. ${item.hostname}`:`${index+1}.`;
      box.append(title);

      const ip=document.createElement('span');
      ip.textContent=`IP: ${item.ip||'не определён'}`;
      const mac=document.createElement('span');
      mac.textContent=`MAC: ${item.mac||'не определён'}`;
      box.append(ip,mac);
      list.append(box);
    });

    dl.before(list);
  }else{
    ipRow.style.display='';
    macRow.style.display='';
    const ips=device.ips?.length?device.ips:[device.ip].filter(Boolean);
    const macs=device.macs?.length?device.macs:[device.mac].filter(Boolean);
    $('.ip',article).textContent=ips.length===1?`${ips[0]} · определён автоматически`:ips.length?`${ips.join(', ')} · определены автоматически`:'не определён · устройство не подключено';
    $('.mac',article).textContent=macs.join(', ')||'—';
  }

  const access=$('.access',article);
  const accessRow=access.closest('div');
  const accessLine=document.createElement('div');
  accessLine.className='access-line';
  accessLine.style.cssText='display:flex;align-items:baseline;gap:4px;margin:14px 0 0;grid-column:1 / -1;white-space:nowrap';
  const accessLabel=document.createElement('span');
  accessLabel.textContent='Доступ:';
  accessLabel.style.color='var(--muted)';
  access.style.flex='0 0 auto';
  access.style.whiteSpace='nowrap';
  access.style.overflowWrap='normal';
  accessLine.append(accessLabel,access);
  if(accessRow)accessRow.replaceWith(accessLine);
  if(!enabled){
    access.textContent='Контроль отключён';
    access.className='access';
  }else if(manual){
    access.textContent='Доступ заблокирован';
    access.className='access blocked';
  }else if(device.whitelist_enforced){
    access.textContent='Только Whitelist';
    access.className='access allowed';
  }else if(temporary){
    access.textContent='Временно разрешён';
    access.className='access allowed';
  }else{
    access.textContent=blocked?'Доступ заблокирован':'Интернет разрешён';
    access.className='access '+(blocked?'blocked':'allowed');
  }

  if(device.speed_limit_enabled&&!blocked){
    dl.after(usageLine('speed-limit',`Скорость ограничена: до ${Number(device.speed_limit_mbps)||0} Мбит/с`));
  }
  if(device.whitelist_enabled){
    const entries=(device.whitelist_entries||[]).length;
    const status=device.whitelist_enforced?'активен':device.whitelist_active?'отключён полной блокировкой':'неактивен';
    dl.after(usageLine('whitelist-status',`Whitelist: ${status}, ${entries} адресов · ${device.whitelist_start||''}–${device.whitelist_end||''}`));
  }
  const reasons=reasonLabels(device);
  if(reasons.length){
    const reason=usageLine('block-reason',reasons.length===1?`Причина: ${reasons[0]}`:`Причины: ${reasons.join(', ')}`);
    dl.style.marginBottom='0';
    reason.style.marginTop='0';
    dl.after(reason);
  }

  const progress=$('.progress',article),daily=$('.daily-usage',article);
  if(device.daily_limit_enabled){
    progress.hidden=false;
    daily.hidden=false;
    const used=Math.max(0,Number(device.used_seconds)||0);
    const limit=Math.max(0,Number(device.daily_limit_seconds)||Number(device.daily_limit_minutes||0)*60);
    progress.firstElementChild.style.width=`${limit?Math.min(100,used/limit*100):0}%`;
    daily.textContent=`Время на сегодня: использовано ${duration(used)} из ${duration(limit)}`;
    daily.after(usageLine('daily-remaining',`Осталось на сегодня: ${duration(Math.max(0,Number(device.daily_remaining_seconds)||0))}`));
  }else{
    progress.hidden=true;
    daily.hidden=true;
  }

  const anchor=article.querySelector('.daily-remaining')||daily;
  if(!manual&&!night&&(cycle||device.break_active)){
    const lines=[];
    if(cycle)lines.push(usageLine('cycle-mode',`Режим: ${device.session_limit_minutes} мин. пользования / ${device.break_minutes} мин. отдыха`));
    if(cycle)lines.push(usageLine('session-left'));
    if(cycle)lines.push(usageLine('traffic-status'));
    lines.push(usageLine('rest-status'));
    lines.push(usageLine('rest-left'));
    anchor.after(...lines);
  }
  if(night){
    anchor.after(usageLine('night-status',`Ночная блокировка до ${device.night_end||''}`));
  }

  const action=$('.action',article);
  if(!enabled){
    action.hidden=true;
  }else if(manual){
    action.textContent='Вернуть доступ';
    action.onclick=()=>command(device.id,'unblock');
  }else if(temporary){
    action.textContent='Вернуть ограничения';
    action.onclick=()=>command(device.id,'reset_temporary_state');
  }else if(night){
    action.hidden=true;
  }else{
    action.textContent='Полностью заблокировать';
    action.onclick=()=>command(device.id,'block');
  }

  $('.more',article).onclick=()=>openEditor(device);
  syncLiveCard(device,article);
  return article;
}

function syncLiveCard(device,element=null){
  element=element||devices.querySelector(`.card[data-id="${CSS.escape(String(device.id))}"]`);
  if(!element)return;

  element.dataset.sessionRemaining=String(Math.max(0,Number(device.session_remaining_seconds)||0));
  element.dataset.breakRemaining=String(Math.max(0,Number(device.break_remaining_seconds)||0));

  const progress=element.querySelector('.progress');
  if(device.daily_limit_enabled&&progress){
    const used=Math.max(0,Number(device.used_seconds)||0);
    const limit=Math.max(0,Number(device.daily_limit_seconds)||Number(device.daily_limit_minutes||0)*60);
    progress.firstElementChild.style.width=`${limit?Math.min(100,used/limit*100):0}%`;
    const daily=element.querySelector('.daily-usage');
    if(daily)daily.textContent=`Время на сегодня: использовано ${duration(used)} из ${duration(limit)}`;
    const remaining=element.querySelector('.daily-remaining');
    if(remaining)remaining.textContent=`Осталось на сегодня: ${duration(Math.max(0,Number(device.daily_remaining_seconds)||0))}`;
  }

  const session=element.querySelector('.session-left');
  const trafficStatus=element.querySelector('.traffic-status');
  const restStatus=element.querySelector('.rest-status');
  const restLeft=element.querySelector('.rest-left');
  if(session){
    session.hidden=!!device.break_active;
    session.textContent=`До отдыха осталось: ${duration(device.session_remaining_seconds)}`;
  }
  if(trafficStatus){trafficStatus.hidden=!device.traffic_idle;trafficStatus.textContent='Устройство не имеет трафика';}
  if(restStatus)restStatus.textContent=device.break_active?'Отдых: активен':'Отдых: неактивен';
  if(restLeft){
    restLeft.hidden=!device.break_active;
    if(device.break_active)restLeft.textContent=`До окончания отдыха: ${duration(device.break_remaining_seconds)}`;
  }
}

function renderState(data){
  latest=(data.devices||[]).map(device=>({...device,state_timestamp:Number(data.state_timestamp)||0}));
  const signature=latest.map(deviceUiSignature).join('|');
  if(signature!==window.__pcUiSignature){
    window.__pcUiSignature=signature;
    devices.replaceChildren(...latest.map(card));
  }else{
    latest.forEach(device=>syncLiveCard(device));
  }
  $('#count-all').textContent=latest.length;
  $('#count-online').textContent=latest.filter(device=>device.ip).length;
  $('#count-blocked').textContent=latest.filter(device=>device.blocked).length;
  $('#service').textContent='Служба работает';
}

async function refresh(){
  if(document.visibilityState!=='visible')return;
  try{renderState(await api('/state'))}
  catch{
    $('#service').textContent='Служба недоступна';
    if(!latest.length)devices.innerHTML='<p>Не удалось получить данные. Проверьте службу parental-control.</p>';
  }
}

async function command(id,action,body={}){
  try{
    await api(`/devices/${encodeURIComponent(id)}/${action}`,{method:'POST',body});
    await refresh();
  }catch(error){
    alert(error.message);
  }
}

const legacyHostname=form.elements.hostname;
const hostList=document.createElement('div');
hostList.id='hostname-list';
legacyHostname.parentNode.replaceChild(hostList,legacyHostname);
const addHost=document.createElement('button');
addHost.type='button';
addHost.className='secondary add-hostname';
addHost.textContent='+ Добавить Hostname';
hostList.after(addHost);
const hostnameEnabled=form.elements.hostname_enabled;
const hostnameToggleLabel=hostnameEnabled.closest('label');
const hostnameEditorLabel=hostList.closest('label');
function syncHostnameEnabled(){
  const enabled=hostnameEnabled.checked;
  hostList.querySelectorAll('input').forEach(input=>{input.disabled=!enabled;input.required=enabled});
  hostList.querySelectorAll('button').forEach(button=>button.disabled=!enabled);
  addHost.disabled=!enabled;
  hostList.closest('label')?.classList.toggle('disabled-field',!enabled);
}
hostnameEnabled.addEventListener('change',syncHostnameEnabled);

function hostRow(value=''){
  const row=document.createElement('div');
  row.className='hostname-row';
  const input=document.createElement('input');
  input.required=hostnameEnabled.checked;
  input.maxLength=127;
  input.value=value;
  input.placeholder='SM-T500';
  const remove=document.createElement('button');
  remove.type='button';
  remove.className='secondary';
  remove.textContent='Удалить';
  remove.onclick=()=>{
    if(hostList.children.length<=1){
      alert('У устройства должен остаться хотя бы один Hostname');
      return;
    }
    row.remove();
  };
  row.append(input,remove);
  hostList.append(row);
  syncHostnameEnabled();
}
addHost.onclick=()=>{if(hostList.children.length>=16){alert('Можно указать не больше 16 Hostname');return;}hostRow();};

const macField=form.elements.mac;
const macLabel=macField.closest('label');
const linkedBox=document.createElement('div');
linkedBox.className='linked-devices';
linkedBox.style.margin='8px 0 18px';
macLabel.after(linkedBox);
const macIpNote=macLabel.previousElementSibling;
const macHelpNote=linkedBox.nextElementSibling;
function showLegacyDeviceFields(show){
  const display=show?'':'none';
  if(hostnameToggleLabel)hostnameToggleLabel.style.display=display;
  if(hostnameEditorLabel)hostnameEditorLabel.style.display=display;
  addHost.style.display=display;
  macLabel.style.display=display;
  if(macIpNote?.classList.contains('ip-note'))macIpNote.style.display=display;
  if(macHelpNote?.classList.contains('ip-note'))macHelpNote.style.display=display;
}

function renumberLinkedDevices(){
  [...linkedBox.querySelectorAll('.linked-device-row')].forEach((row,index)=>{
    const number=row.querySelector('.linked-device-number');
    if(number)number.textContent=`${index+1}.`;
  });
}

function appendLinkedDeviceRow(item={}){
  const row=document.createElement('div');
  row.className='linked-device-row';
  row.dataset.hostname=item.hostname||'';
  row.dataset.mac=item.mac||'';
  row.style.cssText='margin-top:12px;padding:10px 0;border-top:1px solid rgba(127,127,127,.25)';

  const number=document.createElement('strong');
  number.className='linked-device-number';
  row.append(number);

  if(item.hostname){
    const hostname=document.createElement('div');
    hostname.textContent=`Hostname: ${item.hostname}`;
    hostname.style.marginTop='6px';
    row.append(hostname);
  }

  const ip=document.createElement('div');
  ip.textContent=`IP: ${item.ip||'не определён'}`;
  ip.style.marginTop='4px';
  row.append(ip);

  const mac=document.createElement('div');
  mac.textContent=`MAC: ${item.mac||'не определён'}`;
  mac.style.marginTop='4px';
  row.append(mac);

  const remove=document.createElement('button');
  remove.type='button';
  remove.className='secondary';
  remove.textContent='Удалить из профиля';
  remove.style.marginTop='8px';
  remove.onclick=()=>{row.remove();renumberLinkedDevices();};
  row.append(remove);

  linkedBox.append(row);
  renumberLinkedDevices();
}

function renderLinkedDevices(device){
  linkedBox.replaceChildren();
  if(!device){linkedBox.hidden=true;return;}
  linkedBox.hidden=false;

  const title=document.createElement('strong');
  title.textContent='Подключённые устройства';
  linkedBox.append(title);

  const fallbackMacs=(device.macs?.length?device.macs:[device.mac].filter(Boolean));
  const fallbackIps=device.ips||[];
  const linked=(device.linked_devices?.length
    ? device.linked_devices
    : fallbackMacs.map((mac,index)=>({mac,ip:fallbackIps[index]||''})));

  if(linked.length)linked.forEach(appendLinkedDeviceRow);
  else{
    const empty=document.createElement('div');
    empty.className='linked-empty';
    empty.style.marginTop='8px';
    empty.textContent='Нет подключённых устройств';
    linkedBox.append(empty);
  }

  const add=document.createElement('button');
  add.type='button';
  add.className='secondary';
  add.style.marginTop='10px';
  add.textContent='+ Добавить устройство по Hostname';
  add.onclick=()=>{
    if(linkedBox.querySelectorAll('.linked-device-row[data-hostname]').length>=16){
      alert('Можно указать не больше 16 Hostname');
      return;
    }
    const value=prompt('Hostname устройства:','')?.trim();
    if(!value)return;
    if(!/^[A-Za-z0-9._-]{1,127}$/.test(value)){
      alert('Некорректный Hostname');
      return;
    }
    const exists=[...linkedBox.querySelectorAll('.linked-device-row')].some(row=>row.dataset.hostname.toLowerCase()===value.toLowerCase());
    if(exists){alert('Такой Hostname уже добавлен');return;}
    linkedBox.querySelector('.linked-empty')?.remove();
    appendLinkedDeviceRow({hostname:value});
  };
  linkedBox.append(add);
}

const deleteDevice=document.createElement('button');
deleteDevice.type='button';
deleteDevice.className='secondary';
deleteDevice.textContent='Удалить устройство';
deleteDevice.hidden=true;
$('.dialog-actions',form).prepend(deleteDevice);

function normalizeTime(input){
  const match=input.value.trim().match(/^(\d{1,2}):(\d{1,2})$/);
  if(!match)return;
  const h=Number(match[1]),m=Number(match[2]);
  if(h<24&&m<60)input.value=`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
}
for(const name of ['night_start','night_end','whitelist_start','whitelist_end']){
  form.elements[name].addEventListener('blur',()=>normalizeTime(form.elements[name]));
}

function closeEditor(){
  document.activeElement?.blur();
  form.reset();
  hostList.replaceChildren();
  editing=null;
  if(dialog.open)dialog.close();
}

function openEditor(device=null){
  editing=device;
  form.reset();
  hostList.replaceChildren();
  showLegacyDeviceFields(!device);
  renderLinkedDevices(device);

  if(device){
    for(const key of ['name','daily_limit_minutes','session_limit_minutes','break_minutes','speed_limit_mbps','night_start','night_end','whitelist_start','whitelist_end']){
      if(form.elements[key]&&device[key]!==undefined)form.elements[key].value=device[key];
    }
    for(const key of ['daily_limit_enabled','session_limit_enabled','break_enabled','night_enabled','speed_limit_enabled','whitelist_enabled']){
      form.elements[key].checked=!!device[key];
    }
    form.elements.whitelist_entries.value=(device.whitelist_entries||[]).join('\n');
    hostnameEnabled.checked=false;
  }else{
    form.elements.daily_limit_enabled.checked=false;
    form.elements.session_limit_enabled.checked=true;
    form.elements.break_enabled.checked=true;
    form.elements.night_enabled.checked=false;
    form.elements.speed_limit_enabled.checked=false;
    form.elements.speed_limit_mbps.value=5;
    form.elements.whitelist_enabled.checked=false;
    form.elements.whitelist_start.value='08:00';
    form.elements.whitelist_end.value='22:00';
    form.elements.whitelist_entries.value='';
    hostnameEnabled.checked=true;
    hostRow();
  }
  syncHostnameEnabled();

  $('#dialog-title').textContent=device?'Настройки устройства':'Новое устройство';
  deleteDevice.hidden=!device;
  deleteDevice.onclick=async()=>{
    if(!editing||!confirm(`Удалить устройство «${editing.name}»?`))return;
    try{
      await api(`/devices/${encodeURIComponent(editing.id)}`,{method:'DELETE'});
      closeEditor();
      await refresh();
    }catch(error){
      alert(error.message);
    }
  };
  dialog.showModal();
}

$('#add').onclick=()=>openEditor();
form.querySelectorAll('button[value="cancel"],.dialog-head .icon').forEach(button=>{
  button.type='button';
  button.onclick=closeEditor;
});
dialog.addEventListener('cancel',event=>{
  event.preventDefault();
  closeEditor();
});
dialog.addEventListener('click',event=>{
  if(event.target===dialog)closeEditor();
});

form.addEventListener('submit',async event=>{
  event.preventDefault();
  normalizeTime(form.elements.night_start);
  normalizeTime(form.elements.night_end);
  normalizeTime(form.elements.whitelist_start);
  normalizeTime(form.elements.whitelist_end);
  if(!form.reportValidity())return;

  const hostnames=editing
    ? [...linkedBox.querySelectorAll('.linked-device-row')].map(row=>row.dataset.hostname.trim()).filter(Boolean)
    : hostnameEnabled.checked
      ? [...hostList.querySelectorAll('input')].map(input=>input.value.trim()).filter(Boolean)
      : [];
  const normalized=hostnames.map(host=>host.toLowerCase());
  if(new Set(normalized).size!==hostnames.length){
    alert('Hostname не должны повторяться');
    return;
  }
  if(!editing&&hostnameEnabled.checked&&!hostnames.length){
    alert('Укажите хотя бы один Hostname или выключите использование Hostname');
    return;
  }

  const whitelistEntries=[...new Set(form.elements.whitelist_entries.value.split(/[\n,]+/).map(value=>value.trim().toLowerCase()).filter(Boolean))];
  if(form.elements.whitelist_enabled.checked&&!whitelistEntries.length){
    alert('Добавьте хотя бы один домен или IP в Whitelist');
    return;
  }
  if(form.elements.whitelist_enabled.checked&&form.elements.whitelist_start.value===form.elements.whitelist_end.value){
    alert('Начало и конец времени Whitelist должны отличаться');
    return;
  }

  const connectedMacs=editing?[...new Set([...linkedBox.querySelectorAll('.linked-device-row')].map(row=>row.dataset.mac.trim().toLowerCase()).filter(Boolean))]:[];
  const primaryMac=editing?(connectedMacs[0]||''):form.elements.mac.value.trim().toLowerCase();
  const linkedMacs=editing?connectedMacs.slice(1):[];
  const body={
    name:form.elements.name.value.trim(),
    mac:primaryMac,
    linked_macs:linkedMacs,
    hostnames,
    daily_limit_enabled:form.elements.daily_limit_enabled.checked,
    session_limit_enabled:form.elements.session_limit_enabled.checked,
    break_enabled:form.elements.break_enabled.checked,
    night_enabled:form.elements.night_enabled.checked,
    speed_limit_enabled:form.elements.speed_limit_enabled.checked,
    whitelist_enabled:form.elements.whitelist_enabled.checked,
    whitelist_entries:whitelistEntries,
    daily_limit_minutes:Number(form.elements.daily_limit_minutes.value),
    session_limit_minutes:Number(form.elements.session_limit_minutes.value),
    break_minutes:Number(form.elements.break_minutes.value),
    speed_limit_mbps:Number(form.elements.speed_limit_mbps.value),
    night_start:form.elements.night_start.value,
    night_end:form.elements.night_end.value,
    whitelist_start:form.elements.whitelist_start.value,
    whitelist_end:form.elements.whitelist_end.value
  };

  try{
    await api(editing?`/devices/${encodeURIComponent(editing.id)}`:'/devices',{
      method:editing?'PUT':'POST',
      body
    });
    closeEditor();
    await refresh();
  }catch(error){
    alert(error.message);
  }
});

document.addEventListener('visibilitychange',()=>{
  if(document.visibilityState==='visible'){
    if(!socket||socket.readyState!==WebSocket.OPEN)connectSocket().catch(()=>{});
    else refresh();
  }
});

$('#theme').onclick=()=>{
  const dark=document.documentElement.dataset.theme!=='dark';
  document.documentElement.dataset.theme=dark?'dark':'';
  localStorage.pcTheme=dark?'dark':'light';
};
if(localStorage.pcTheme==='dark')document.documentElement.dataset.theme='dark';

connectSocket().then(refresh).catch(()=>scheduleReconnect());
