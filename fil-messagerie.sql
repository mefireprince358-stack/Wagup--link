-- ===== WAGUP LINK : fil de demandes + messagerie (relançable, aucune donnée supprimée) =====
alter table public.conversations
  add column if not exists origin text not null default 'contact',
  add column if not exists status text not null default 'open';
alter table public.conversations drop constraint if exists conv_origin_check;
alter table public.conversations add constraint conv_origin_check check (origin in ('interest','contact'));
alter table public.conversations drop constraint if exists conv_status_check;
alter table public.conversations add constraint conv_status_check check (status in ('open','declined'));

-- Refus d'un professionnel : réservé au client propriétaire de la demande
create or replace function public.decline_interest(cid uuid) returns void language plpgsql security definer set search_path=public as
$$ declare rid uuid; pid uuid; begin
 update conversations set status='declined' where id=cid and client_id=auth.uid() returning request_id,pro_id into rid,pid;
 if not found then raise exception 'interdit'; end if;
 update requests set status='open', chosen_pro_id=null where id=rid and chosen_pro_id=pid;
end $$;
revoke execute on function public.decline_interest(uuid) from public, anon;
grant execute on function public.decline_interest(uuid) to authenticated;

-- Politiques mises à jour (mêmes règles qu'avant + gestion du refus)
drop policy if exists conv_insert on public.conversations;
create policy conv_insert on public.conversations for insert to authenticated with check(
 (auth.uid()=client_id or auth.uid()=pro_id) and status='open' and can_act() and can_converse(request_id,client_id,pro_id)
 and not exists(select 1 from blocks b where (b.blocker_id=client_id and b.blocked_id=pro_id) or (b.blocker_id=pro_id and b.blocked_id=client_id)));

drop policy if exists msg_insert on public.messages;
create policy msg_insert on public.messages for insert to authenticated with check(sender_id=auth.uid() and can_act()
 and exists(select 1 from conversations c where c.id=messages.conversation_id and c.status='open' and (auth.uid()=c.client_id or auth.uid()=c.pro_id))
 and not exists(select 1 from blocks b join conversations c on c.id=messages.conversation_id
   where (b.blocker_id=c.client_id and b.blocked_id=c.pro_id) or (b.blocker_id=c.pro_id and b.blocked_id=c.client_id)));

drop policy if exists req_update on public.requests;
create policy req_update on public.requests for update to authenticated using(client_id=auth.uid())
 with check(client_id=auth.uid() and (chosen_pro_id is null or exists(select 1 from conversations c
  where c.request_id=requests.id and c.pro_id=requests.chosen_pro_id and c.status='open')));
