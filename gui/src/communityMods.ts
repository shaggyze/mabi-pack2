import {invoke} from './platform/invoke';
import {isTauri} from './platform/isTauri';

interface Mod {id:string;title:string;version:string;private:boolean;format:string;revision:string}
interface Result {connected:boolean;owner:string;mods:Mod[];subscriptions:Record<string,{revision:string}>;updated:string[];errors:string[]}
type Translate=(key:string,args?:string[])=>string;

/** Account-specific downloads are separate from the public numeric mod catalog. */
export function setupCommunityMods(t:Translate,log:(message:string,level:'info'|'warn')=>void,openUrl:(url:string)=>void):void{
    if(!isTauri())return;
    const parent=document.querySelector('#mods .mods-panel');if(!parent)return;
    const section=document.createElement('section');section.className='card community-card';
    const heading=document.createElement('h3');heading.textContent=t('community_title');
    const help=document.createElement('p');help.textContent=t('community_help');
    const link=document.createElement('a');link.href='https://shaggyze.website/mabipatcher/upload';link.textContent=t('community_website');link.className='community-link';
    // The main window has no tabs: open the page in the app's Browser tab.
    link.addEventListener('click',event=>{event.preventDefault();openUrl(link.href);});
    const label=document.createElement('label');label.textContent=t('community_key');
    const input=document.createElement('input');input.type='password';input.autocomplete='off';input.className='form-input';input.maxLength=69;
    // Show/hide so a pasted key can be checked before Connect.
    const reveal=document.createElement('button');reveal.type='button';reveal.className='tab-btn';reveal.textContent=t('community_show');
    reveal.setAttribute('aria-pressed','false');
    reveal.onclick=()=>{const show=input.type==='password';input.type=show?'text':'password';reveal.textContent=t(show?'community_hide':'community_show');reveal.setAttribute('aria-pressed',String(show));};
    const keyRow=document.createElement('div');keyRow.style.cssText='display:flex;gap:6px;align-items:center';input.style.flex='1';keyRow.append(input,reveal);label.append(keyRow);
    const status=document.createElement('p');status.className='community-status';status.setAttribute('role','status');
    const setStatus=(text:string,state:'ok'|'error'|'idle')=>{status.textContent=text;status.dataset.state=state;};
    let connected='',lastError='',lastErrors='',lastOk='';
    const list=document.createElement('div');let busy=false;
    const controls:HTMLButtonElement[]=[];
    const button=(text:string,action:()=>Promise<Result>)=>{
        const node=document.createElement('button');node.className='tab-btn';node.textContent=text;
        node.onclick=()=>void run(action);controls.push(node);return node;
    };
    async function run(action:()=>Promise<Result>){
        if(busy)return;busy=true;controls.forEach(b=>b.disabled=true);input.disabled=true;
        try{render(await action());}catch(error){const text=t('community_failed',[String(error)]);
            // Keep a confirmed connection visible above a sync error.
            setStatus(connected?`${connected} · ${text}`:text,'error');
            // The 5-minute refresh repeats the same failure; log it once.
            if(text!==lastError)log(text,'warn');lastError=text;lastOk='';}
        finally{busy=false;controls.forEach(b=>b.disabled=false);input.disabled=false;}
    }
    const sync=()=>invoke<Result>('community_mod_sync');
    const connect=button(t('community_connect'),async()=>{
        const token=input.value.trim();input.value='';input.type='password';reveal.textContent=t('community_show');reveal.setAttribute('aria-pressed','false');
        // Report the connection on its own so a later sync error cannot hide it.
        const owner=await invoke<string>('community_mod_connect',{token});
        connected=t('community_connected',[owner]);setStatus(connected,'ok');log(connected,'info');
        return sync();
    });
    const refresh=button(t('community_refresh'),sync);
    const disconnect=button(t('community_disconnect'),async()=>{await invoke('community_mod_disconnect');return sync();});
    function render(result:Result){
        // Drop row controls before rerendering so periodic refresh does not grow memory.
        controls.splice(3);list.replaceChildren();
        lastError='';connected=result.connected?t('community_connected',[result.owner]):'';
        if(connected)setStatus(connected,'ok');else setStatus(t('community_disconnected'),'idle');
        // A working sync logs once, then again when the counts change or after an error.
        // A key that stopped working logs the disconnect; a fresh start without a key does not.
        const ok=result.connected?t('community_sync_ok',[String(result.mods.length),String(Object.keys(result.subscriptions).length)]):lastOk?t('community_disconnected'):'';
        if(ok&&ok!==lastOk)log(ok,'info');lastOk=ok;
        if(result.updated.length)log(t('community_updated',[result.updated.join(', ')]),'info');
        // Per-mod errors repeat on every refresh; log them when they change.
        const errs=result.errors.join('|');if(errs&&errs!==lastErrors)for(const e of result.errors)log(t('community_failed',[e]),'warn');lastErrors=errs;
        if(result.errors.length){const error=document.createElement('p');error.textContent=result.errors.join(' · ');list.append(error);}
        for(const mod of result.mods){
            const row=document.createElement('div');row.className='mod-item';
            const name=document.createElement('strong');name.textContent=mod.title;
            const detail=document.createElement('p');detail.textContent=[mod.version,mod.private?t('community_private'):t('community_public'),mod.format.toUpperCase()].filter(Boolean).join(' · ');
            row.append(name,detail);
            const subscribed=!!result.subscriptions[mod.id];
            if(['it','pack'].includes(mod.format))row.append(button(t(subscribed?'community_stop':'community_install'),()=>invoke<Result>('community_mod_sync',subscribed?{unsubscribe:mod.id}:{subscribe:mod.id})));
            else{const note=document.createElement('small');note.textContent=t('community_manual');row.append(note);}
            list.append(row);
        }
        if(result.connected&&!result.mods.length){const empty=document.createElement('p');empty.textContent=t('community_empty');list.append(empty);}
    }
    // Buttons share one row; a flex column card would stretch each to full width.
    const actions=document.createElement('div');actions.className='form-actions';actions.append(connect,refresh,disconnect);
    section.append(heading,help,link,label,actions,status,list);parent.append(section);
    void run(sync);
    // Only explicit subscriptions update; the native backend serializes all
    // connection and sync operations and validates every downloaded package.
    window.setInterval(()=>void run(sync),5*60*1000);
}
