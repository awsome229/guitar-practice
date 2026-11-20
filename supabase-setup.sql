-- Guitar Practice: tables, members-only rules and riff storage.
-- Paste all of this into Supabase > SQL Editor and click Run. Safe to run once.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  name text not null default '' check (char_length(name) <= 30),
  data jsonb not null default '{}'::jsonb check (pg_column_size(data) < 200000),
  updated_at timestamptz not null default now()
);

create table public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 40),
  code text not null unique,
  owner uuid not null default auth.uid() references auth.users on delete cascade,
  song text not null default '' check (char_length(song) <= 60),
  content jsonb not null default '{}'::jsonb check (pg_column_size(content) < 100000),
  created_at timestamptz not null default now()
);

create table public.members (
  group_id uuid references public.groups on delete cascade,
  user_id uuid references auth.users on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);

create table public.posts (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.groups on delete cascade,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  kind text not null check (kind in ('riff', 'milestone')),
  body text not null default '' check (char_length(body) <= 200),
  audio text,
  created_at timestamptz not null default now()
);
create index on public.posts (group_id, created_at desc);

-- Reactions are emoji only, from a fixed set.
create table public.reactions (
  post_id uuid references public.posts on delete cascade,
  user_id uuid default auth.uid() references auth.users on delete cascade,
  emoji text not null check (emoji in ('🔥','👏','🎸','🤘','😂','❤️','🤯','💯')),
  primary key (post_id, user_id, emoji)
);

-- Helpers the rules use. security definer so they can look at members without looping back into its own rules.
create function public.is_member(g uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where group_id = g and user_id = auth.uid())
$$;

create function public.shares_group(u uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members a join members b on a.group_id = b.group_id
                 where a.user_id = auth.uid() and b.user_id = u)
$$;

-- Making a group and joining by code go through these, so nobody can add themselves to a group without its code.
create function public.create_group(gname text) returns uuid
language plpgsql security definer set search_path = public as $$
declare g uuid; c text;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  if (select count(*) from groups where owner = auth.uid()) >= 3 then raise exception 'You can own up to 3 groups'; end if;
  loop
    c := '';
    for i in 1..6 loop
      c := c || substr('ABCDEFGHJKMNPQRSTUVWXYZ23456789', 1 + floor(random() * 31)::int, 1);
    end loop;
    exit when not exists (select 1 from groups where code = c);
  end loop;
  insert into groups (name, code, owner) values (left(trim(gname), 40), c, auth.uid()) returning id into g;
  insert into members (group_id, user_id) values (g, auth.uid());
  return g;
end $$;

create function public.join_group(jcode text) returns uuid
language plpgsql security definer set search_path = public as $$
declare g uuid;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  select id into g from groups where code = upper(trim(jcode));
  if g is null then raise exception 'No group has that code'; end if;
  if (select count(*) from members where group_id = g) >= 20 then raise exception 'That group is full'; end if;
  insert into members (group_id, user_id) values (g, auth.uid()) on conflict do nothing;
  return g;
end $$;

revoke execute on function public.create_group(text), public.join_group(text) from public, anon;
grant execute on function public.create_group(text), public.join_group(text) to authenticated;

-- Rules: only signed-in members of a group can see or change its things.
alter table public.profiles enable row level security;
alter table public.groups enable row level security;
alter table public.members enable row level security;
alter table public.posts enable row level security;
alter table public.reactions enable row level security;

create policy "see own and groupmates" on public.profiles for select to authenticated
  using (id = auth.uid() or public.shares_group(id));
create policy "insert own" on public.profiles for insert to authenticated with check (id = auth.uid());
create policy "update own" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

create policy "members see group" on public.groups for select to authenticated using (public.is_member(id));
create policy "owner edits group" on public.groups for update to authenticated
  using (owner = auth.uid()) with check (owner = auth.uid());

create policy "members see members" on public.members for select to authenticated using (public.is_member(group_id));
create policy "leave group" on public.members for delete to authenticated using (user_id = auth.uid());

create policy "members see posts" on public.posts for select to authenticated using (public.is_member(group_id));
create policy "members post" on public.posts for insert to authenticated
  with check (user_id = auth.uid() and public.is_member(group_id)
              and (audio is null or audio like group_id::text || '/' || auth.uid()::text || '/%'));
create policy "delete own post" on public.posts for delete to authenticated using (user_id = auth.uid());

create policy "members see reactions" on public.reactions for select to authenticated
  using (exists (select 1 from public.posts p where p.id = post_id and public.is_member(p.group_id)));
create policy "members react" on public.reactions for insert to authenticated
  with check (user_id = auth.uid() and exists (select 1 from public.posts p where p.id = post_id and public.is_member(p.group_id)));
create policy "remove own reaction" on public.reactions for delete to authenticated using (user_id = auth.uid());

grant select, insert, update, delete on public.profiles, public.groups, public.members, public.posts, public.reactions to authenticated;

-- Riff storage: private, audio only, 2 MB per file. Files live at <group id>/<user id>/<file>.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('riffs', 'riffs', false, 2097152, array['audio/*']);

create policy "members hear riffs" on storage.objects for select to authenticated
  using (bucket_id = 'riffs' and public.is_member(((storage.foldername(name))[1])::uuid));
create policy "members upload own riffs" on storage.objects for insert to authenticated
  with check (bucket_id = 'riffs' and public.is_member(((storage.foldername(name))[1])::uuid)
              and (storage.foldername(name))[2] = auth.uid()::text);
create policy "delete own riffs" on storage.objects for delete to authenticated
  using (bucket_id = 'riffs' and (storage.foldername(name))[2] = auth.uid()::text);
