-- ===== WAGUP LINK : SÉCURITÉ v2 (audité, relançable sans danger, tout ou rien) =====
-- 1. Colonnes
alter table public.profiles add column if not exists status text not null default 'active',
  add column if not exists warnings int not null default 0,
  add column if not exists deleted_requests int not null default 0;
alter table public.profiles drop constraint if exists profiles_status_check;
alter table public.profiles add constraint profiles_status_check check (status in ('active','under_review','suspended','banned'));
update public.profiles set status='suspended' where suspended and status='active';

alter table public.professionals add column if not exists verification_status text not null default 'pending',
  add column if not exists verified_at timestamptz;
alter table public.professionals drop constraint if exists pro_verif_check;
alter table public.professionals add constraint pro_verif_check check (verification_status in ('pending','verified','rejected'));

alter table public.requests add column if not exists desired_date text,
  add column if not exists confirmed_real boolean not null default false;

alter table public.reports add column if not exists target_id uuid references public.profiles(id) on delete set null,
  add column if not exists category text, add column if not exists status text not null default 'open';
create unique index if not exists reports_unique on public.reports(reporter_id,target_id,category) where target_id is not null;

create index if not exists idx_msg_sender_time on public.messages(sender_id,created_at);
create index if not exists idx_req_client_time on public.requests(client_id,created_at);
create index if not exists idx_rep_reporter_time on public.reports(reporter_id,created_at);
create index if not exists idx_rep_target on public.reports(target_id);

-- 2. Synchronisation ancien champ « suspended »
create or replace function public.sync_suspended() returns trigger language plpgsql as
$$ begin
 if tg_op='INSERT' or new.status is distinct from old.status then new.suspended := new.status in ('suspended','banned');
 elsif new.suspended is distinct from old.suspended then new.status := case when new.suspended then 'suspended' else 'active' end;
 end if; return new; end $$;
drop trigger if exists trg_sync_suspended on public.profiles;
create trigger trg_sync_suspended before insert or update on public.profiles for each row execute function public.sync_suspended();

-- 3. Vérification du téléphone (mettre 'true' quand le SMS est configuré, voir explications)
do $$ begin
 if not exists(select 1 from pg_proc where proname='phone_required' and pronamespace='public'::regnamespace) then
  execute 'create function public.phone_required() returns boolean language sql stable as ''select false''';
 end if; end $$;
create or replace function public.is_phone_verified() returns boolean language sql stable security definer set search_path=public,auth as
$$ select coalesce((select phone_confirmed_at is not null from auth.users where id=auth.uid()),false) $$;
create or replace function public.can_act() returns boolean language sql stable security definer set search_path=public as
$$ select is_active() and (not phone_required() or is_phone_verified()) $$;

-- 4. Fonctions administrateur (contrôle du rôle côté serveur)
create or replace function public.admin_set_status(uid uuid,s text) returns void language plpgsql security definer set search_path=public as
$$ begin if not is_admin() then raise exception 'interdit'; end if;
 update profiles set status=s where id=uid and role<>'admin'; end $$;
create or replace function public.admin_set_suspended(uid uuid,s boolean) returns void language plpgsql security definer set search_path=public as
$$ begin if not is_admin() then raise exception 'interdit'; end if;
 update profiles set status=case when s then 'suspended' else 'active' end where id=uid and role<>'admin'; end $$;
create or replace function public.admin_warn(uid uuid) returns void language plpgsql security definer set search_path=public as
$$ begin if not is_admin() then raise exception 'interdit'; end if;
 update profiles set warnings=warnings+1, status=case when warnings+1>=3 and status='active' then 'under_review' else status end
 where id=uid and role<>'admin'; end $$;
create or replace function public.admin_verify_pro(uid uuid,ok boolean) returns void language plpgsql security definer set search_path=public as
$$ begin if not is_admin() then raise exception 'interdit'; end if;
 update professionals set verification_status=case when ok then 'verified' else 'rejected' end,
  verified_at=case when ok then now() else null end where id=uid; end $$;
drop function if exists public.admin_overview();
create or replace function public.admin_overview() returns table(id uuid,status text,warnings int,deleted_requests int,reports_count bigint,phone_verified boolean,vstatus text)
language plpgsql security definer set search_path=public,auth as
$$ begin if not is_admin() then raise exception 'interdit'; end if;
 return query select p.id,p.status,p.warnings,p.deleted_requests,(select count(*) from reports r where r.target_id=p.id),
  (u.phone_confirmed_at is not null),(select pr.verification_status from professionals pr where pr.id=p.id)
 from profiles p join auth.users u on u.id=p.id; end $$;

-- 5. Détection des comportements suspects (jamais de bannissement automatique)
create or replace function public.trg_report_after() returns trigger language plpgsql security definer set search_path=public as
$$ begin
 if new.target_id is not null and (select count(distinct reporter_id) from reports where target_id=new.target_id)>=3 then
  update profiles set status='under_review' where id=new.target_id and status='active' and role<>'admin'; end if;
 return new; end $$;
drop trigger if exists trg_report_after on public.reports;
create trigger trg_report_after after insert on public.reports for each row execute function public.trg_report_after();

create or replace function public.trg_request_del() returns trigger language plpgsql security definer set search_path=public as
$$ begin
 update profiles set deleted_requests=deleted_requests+1,
  status=case when deleted_requests+1>=5 and status='active' then 'under_review' else status end where id=old.client_id;
 return old; end $$;
drop trigger if exists trg_request_del on public.requests;
create trigger trg_request_del after delete on public.requests for each row execute function public.trg_request_del();

-- 6. Anti-spam
create or replace function public.trg_request_limit() returns trigger language plpgsql security definer set search_path=public as
$$ begin
 if (select count(*) from requests where client_id=new.client_id and created_at>now()-interval '24 hours')>=5 then
  raise exception 'Limite de demandes atteinte (5 par 24 h).'; end if;
 if exists(select 1 from requests where client_id=new.client_id and lower(title)=lower(new.title) and created_at>now()-interval '10 minutes') then
  raise exception 'Doublon : cette demande vient déjà d''être publiée.'; end if;
 return new; end $$;
drop trigger if exists trg_request_limit on public.requests;
create trigger trg_request_limit before insert on public.requests for each row execute function public.trg_request_limit();

create or replace function public.trg_msg_limit() returns trigger language plpgsql security definer set search_path=public as
$$ begin
 if (select count(*) from messages where sender_id=new.sender_id and created_at>now()-interval '1 minute')>=20 then
  raise exception 'Limite : trop de messages en peu de temps.'; end if;
 return new; end $$;
drop trigger if exists trg_msg_limit on public.messages;
create trigger trg_msg_limit before insert on public.messages for each row execute function public.trg_msg_limit();

create or replace function public.trg_report_limit() returns trigger language plpgsql security definer set search_path=public as
$$ begin
 if (select count(*) from reports where reporter_id=new.reporter_id and created_at>now()-interval '24 hours')>=10 then
  raise exception 'Limite : trop de signalements aujourd''hui.'; end if;
 return new; end $$;
drop trigger if exists trg_report_limit on public.reports;
create trigger trg_report_limit before insert on public.reports for each row execute function public.trg_report_limit();

-- 7. Politiques (RLS)
drop policy if exists req_insert on public.requests;
create policy req_insert on public.requests for insert to authenticated with check(
 client_id=auth.uid() and can_act() and confirmed_real and length(trim(title))>=5 and length(trim(coalesce(description,'')))>=20 and length(trim(coalesce(desired_date,'')))>=2);
drop policy if exists conv_insert on public.conversations;
create policy conv_insert on public.conversations for insert to authenticated with check(
 (auth.uid()=client_id or auth.uid()=pro_id) and can_act() and can_converse(request_id,client_id,pro_id)
 and not exists(select 1 from blocks b where (b.blocker_id=client_id and b.blocked_id=pro_id) or (b.blocker_id=pro_id and b.blocked_id=client_id)));
drop policy if exists req_update on public.requests;
create policy req_update on public.requests for update to authenticated using(client_id=auth.uid())
 with check(client_id=auth.uid() and (chosen_pro_id is null or exists(select 1 from conversations c where c.request_id=requests.id and c.pro_id=requests.chosen_pro_id)));
drop policy if exists blocks_insert on public.blocks;
create policy blocks_insert on public.blocks for insert to authenticated with check(blocker_id=auth.uid() and blocked_id<>auth.uid());
drop policy if exists msg_insert on public.messages;
create policy msg_insert on public.messages for insert to authenticated with check(sender_id=auth.uid() and can_act()
 and exists(select 1 from conversations c where c.id=messages.conversation_id and (auth.uid()=c.client_id or auth.uid()=c.pro_id))
 and not exists(select 1 from blocks b join conversations c on c.id=messages.conversation_id
   where (b.blocker_id=c.client_id and b.blocked_id=c.pro_id) or (b.blocker_id=c.pro_id and b.blocked_id=c.client_id)));
drop policy if exists reports_insert on public.reports;
create policy reports_insert on public.reports for insert to authenticated with check(
 reporter_id=auth.uid() and target_id is not null and target_id<>auth.uid() and is_active()
 and category in ('Fausse demande','Faux professionnel','Comportement inapproprié','Arnaque','Spam','Autre'));

-- 8. Droits par colonne (personne ne peut se donner un statut, un rôle ou une vérification)
revoke update on public.profiles from authenticated;
grant update(name) on public.profiles to authenticated;
revoke update on public.requests from authenticated;
grant update(status,chosen_pro_id) on public.requests to authenticated;
revoke update on public.messages from authenticated;
grant update(read_at) on public.messages to authenticated;
revoke update on public.professionals from authenticated;
grant update(bio,exp_years,zone,services) on public.professionals to authenticated;
revoke select on public.profiles from authenticated;
grant select(id,role,name,suspended,created_at) on public.profiles to authenticated;

-- 9. Droits d'exécution des fonctions (rien d'exposé au public non connecté)
revoke execute on function public.admin_set_status(uuid,text),public.admin_set_suspended(uuid,boolean),public.admin_warn(uuid),
 public.admin_verify_pro(uuid,boolean),public.admin_overview() from public,anon;
grant execute on function public.admin_set_status(uuid,text),public.admin_set_suspended(uuid,boolean),public.admin_warn(uuid),
 public.admin_verify_pro(uuid,boolean),public.admin_overview() to authenticated;
revoke execute on function public.sync_suspended(),public.trg_report_after(),public.trg_request_del(),public.trg_request_limit(),
 public.trg_msg_limit(),public.trg_report_limit() from public,anon,authenticated;
revoke execute on function public.is_admin(),public.is_active(),public.can_converse(uuid,uuid,uuid),public.can_act(),
 public.is_phone_verified(),public.phone_required() from public,anon;
grant execute on function public.is_admin(),public.is_active(),public.can_converse(uuid,uuid,uuid),public.can_act(),
 public.is_phone_verified(),public.phone_required() to authenticated;
do $$ begin if to_regprocedure('public.admin_stats()') is not null then
 execute 'revoke execute on function public.admin_stats() from public,anon'; end if; end $$;
