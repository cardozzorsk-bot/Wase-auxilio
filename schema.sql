-- Execute este arquivo no SQL Editor do seu projeto Supabase.
create table if not exists public.wase_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.wase_keys (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  client_name text,
  device_id text,
  expires_at timestamptz not null,
  blocked boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.wase_admins enable row level security;
alter table public.wase_keys enable row level security;
revoke all on public.wase_admins, public.wase_keys from anon, authenticated;

create or replace function public.admin_is_authorized() returns boolean
language sql security definer set search_path=public as $$
 select exists(select 1 from public.wase_admins where user_id=auth.uid());
$$;
create or replace function public.client_validate_key(p_code text)
returns table(expires_at timestamptz) language sql security definer set search_path=public as $$
 select k.expires_at from public.wase_keys k
 where k.code=p_code and k.blocked=false and k.expires_at>now() limit 1;
$$;
create or replace function public.admin_create_key(p_code text,p_days integer) returns uuid
language plpgsql security definer set search_path=public as $$
declare new_id uuid;
begin
 if not public.admin_is_authorized() then raise exception 'not authorized'; end if;
 if p_days not between 1 and 365 then raise exception 'invalid duration'; end if;
 insert into public.wase_keys(code,expires_at) values(p_code,now()+make_interval(days=>p_days)) returning id into new_id;
 return new_id;
end; $$;
create or replace function public.admin_list_keys() returns table(id uuid,code text,client_name text,device_id text,expires_at timestamptz,blocked boolean,created_at timestamptz)
language plpgsql security definer set search_path=public as $$
begin
 if not public.admin_is_authorized() then raise exception 'not authorized'; end if;
 return query select k.id,k.code,k.client_name,k.device_id,k.expires_at,k.blocked,k.created_at from public.wase_keys k order by k.created_at desc;
end; $$;
create or replace function public.admin_bind_key(p_code text,p_client_name text,p_device_id text) returns void
language plpgsql security definer set search_path=public as $$
begin
 if not public.admin_is_authorized() then raise exception 'not authorized'; end if;
 update public.wase_keys set client_name=p_client_name,device_id=p_device_id where code=p_code;
 if not found then raise exception 'key not found'; end if;
end; $$;
create or replace function public.admin_set_key_blocked(p_id uuid,p_blocked boolean) returns void
language plpgsql security definer set search_path=public as $$
begin
 if not public.admin_is_authorized() then raise exception 'not authorized'; end if;
 update public.wase_keys set blocked=p_blocked where id=p_id;
end; $$;
create or replace function public.admin_delete_key(p_id uuid) returns void
language plpgsql security definer set search_path=public as $$
begin
 if not public.admin_is_authorized() then raise exception 'not authorized'; end if;
 delete from public.wase_keys where id=p_id;
end; $$;
grant execute on function public.admin_is_authorized() to authenticated;
grant execute on function public.client_validate_key(text) to anon, authenticated;
grant execute on function public.admin_create_key(text,integer), public.admin_list_keys(), public.admin_bind_key(text,text,text), public.admin_set_key_blocked(uuid,boolean), public.admin_delete_key(uuid) to authenticated;
-- Depois de criar o usuário administrador em Authentication > Users, execute:
-- insert into public.wase_admins(user_id) values ('UUID_DO_USUARIO_ADMIN');
