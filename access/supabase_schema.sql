-- AnokhiDrishti temporary access control: the Supabase (Postgres) store.
--
-- Paste into Supabase -> SQL Editor -> New query -> Run.  Safe to run again:
-- every statement is create-if-missing or create-or-replace.
--
-- The tables mirror access/store.py's SQLite schema column for column, so the
-- service code above the store does not change with the backend.  Timestamps
-- stay TEXT in the one fixed format access.policy.stamp() writes
-- (2026-09-30T12:32:11.968Z) and compare byte-wise (COLLATE "C"), which is
-- exactly how SQLite compares them.
--
-- Who can touch it: only the server, through the project's secret key (the
-- service_role).  Row-level security is on with no policies, and the anon and
-- authenticated roles - what the public keys map to - have every privilege
-- revoked, so a leaked publishable key reads nothing.
--
-- The audit log is enforced by the database, not only by the server: rows can
-- be added but never changed or removed, and a row is refused unless its hash
-- is right and it links to the row before it.  The server's own key cannot
-- rewrite history.

-- ---------------------------------------------------------------- tables --

create table if not exists public.access_users (
    id               bigint generated always as identity primary key,
    username         text    not null unique,
    password_hash    text    not null,
    role             text    not null default 'user'
                             check (role in ('user', 'admin')),
    created_utc      text collate "C" not null,
    last_login_utc   text collate "C",
    failed_count     integer not null default 0,
    first_fail_utc   text collate "C",
    locked_until_utc text collate "C",
    disabled         integer not null default 0 check (disabled in (0, 1)),
    email            text
);
-- Added 1 Oct 2026 for the mail notices; brings a table made earlier up to date.
alter table public.access_users add column if not exists email text;

create table if not exists public.access_requests (
    id                  bigint generated always as identity primary key,
    public_id           text not null unique,
    user_id             bigint not null references public.access_users(id),
    status              text not null check (status in
                        ('pending', 'approved', 'active',
                         'rejected', 'expired', 'revoked')),
    created_utc         text collate "C" not null,
    request_expires_utc text collate "C" not null,
    decided_utc         text collate "C",
    decided_by          text,
    decision_note       text,
    access_expires_utc  text collate "C",
    activated_utc       text collate "C",
    closed_utc          text collate "C",
    remote_ip           text,
    user_agent          text
);
create index if not exists ix_access_requests_status on public.access_requests(status);
create index if not exists ix_access_requests_user   on public.access_requests(user_id);

create table if not exists public.access_sessions (
    id            bigint generated always as identity primary key,
    token_hash    text not null unique,
    user_id       bigint not null references public.access_users(id),
    request_id    bigint references public.access_requests(id),
    kind          text not null,
    created_utc   text collate "C" not null,
    expires_utc   text collate "C" not null,
    last_seen_utc text collate "C",
    remote_ip     text,
    user_agent    text,
    revoked_utc   text collate "C"
);
create index if not exists ix_access_sessions_user    on public.access_sessions(user_id);
create index if not exists ix_access_sessions_request on public.access_sessions(request_id);

-- One row per audit entry.  `entry` is the exact canonical JSON the hash
-- covers (core.contract.canonical_json of the entry without entry_hash), so
-- the chain can be re-verified from this table alone.
create table if not exists public.access_audit (
    seq        integer primary key check (seq >= 0),
    prev_hash  text not null,
    entry_hash text not null unique,
    entry      text not null,
    stored_at  timestamptz not null default now()
);

-- The ledger seal (HMAC over count and head), one row per seal key.  It moves
-- forward with the log, so unlike the log itself it is updatable.
create table if not exists public.access_audit_seal (
    key_id      text primary key,
    count       integer not null,
    head        text not null,
    hmac        text not null,
    updated_utc text collate "C" not null
);

-- ------------------------------------------------ audit log: append-only --

create or replace function public.access_audit_refuse_change()
returns trigger language plpgsql set search_path = '' as $$
begin
    raise exception 'access_audit is append-only: % refused', tg_op;
end $$;

drop trigger if exists access_audit_no_update on public.access_audit;
create trigger access_audit_no_update
    before update or delete on public.access_audit
    for each row execute function public.access_audit_refuse_change();

drop trigger if exists access_audit_no_truncate on public.access_audit;
create trigger access_audit_no_truncate
    before truncate on public.access_audit
    for each statement execute function public.access_audit_refuse_change();

-- A new entry must hash to its entry_hash, carry the seq and prev_hash its
-- columns claim, and link to the entry before it (64 zeros for the first).
create or replace function public.access_audit_check_link()
returns trigger language plpgsql set search_path = '' as $$
declare
    body     jsonb;
    prev_row record;
begin
    if encode(sha256(convert_to(new.entry, 'UTF8')), 'hex') <> new.entry_hash then
        raise exception 'audit entry %: entry_hash does not match its content', new.seq;
    end if;
    body := new.entry::jsonb;
    if (body ->> 'seq')::integer is distinct from new.seq
       or body ->> 'prev_hash' is distinct from new.prev_hash then
        raise exception 'audit entry %: seq or prev_hash differs from its content', new.seq;
    end if;
    if new.seq = 0 then
        if new.prev_hash <> repeat('0', 64) then
            raise exception 'audit entry 0 must link to 64 zeros';
        end if;
        return new;
    end if;
    select seq, entry_hash into prev_row
      from public.access_audit where seq = new.seq - 1;
    if not found then
        raise exception 'audit entry %: entry % is missing', new.seq, new.seq - 1;
    end if;
    if prev_row.entry_hash <> new.prev_hash then
        raise exception 'audit entry %: does not link to entry %', new.seq, new.seq - 1;
    end if;
    return new;
end $$;

drop trigger if exists access_audit_link on public.access_audit;
create trigger access_audit_link
    before insert on public.access_audit
    for each row execute function public.access_audit_check_link();

-- ------------------------------------ statements REST cannot express alone --
-- The state names are passed in rather than written here, so access/policy.py
-- stays the one place they are defined.

-- Bump the failed-sign-in counter and return the new count.
create or replace function public.access_note_login_fail(
    p_user_id bigint, p_restart boolean, p_now text)
returns integer language sql set search_path = '' as $$
    update public.access_users set
        failed_count   = case when p_restart then 1 else failed_count + 1 end,
        first_fail_utc = case when p_restart then p_now
                              else coalesce(first_fail_utc, p_now) end
     where id = p_user_id
    returning failed_count;
$$;

-- Move a request to a terminal state; empty p_only_if means from any state.
create or replace function public.access_close_request(
    p_request_id bigint, p_status text, p_now text, p_by text,
    p_note text, p_only_if text[])
returns setof public.access_requests language sql set search_path = '' as $$
    update public.access_requests set
        status        = p_status,
        closed_utc    = p_now,
        decision_note = p_note,
        decided_by    = case when coalesce(p_by, '') <> ''
                             then coalesce(decided_by, p_by) else decided_by end
     where id = p_request_id
       and (coalesce(cardinality(p_only_if), 0) = 0 or status = any(p_only_if))
    returning *;
$$;

-- Requests whose clock has run out but whose status lags behind.
create or replace function public.access_due_requests(
    p_now text, p_pending text, p_granting text[])
returns setof public.access_requests language sql stable set search_path = '' as $$
    select * from public.access_requests
     where (status = p_pending
            and request_expires_utc <= p_now collate "C")
        or (status = any(p_granting)
            and access_expires_utc is not null
            and access_expires_utc <= p_now collate "C");
$$;

-- Requests newest first, each with its user's name.
create or replace function public.access_list_requests(
    p_statuses text[], p_limit integer, p_user_id bigint)
returns jsonb language sql stable set search_path = '' as $$
    select coalesce(jsonb_agg(to_jsonb(r) || jsonb_build_object('username', u.username,
                                                              'email', u.email)
                              order by r.id desc), '[]'::jsonb)
      from (select * from public.access_requests
             where (coalesce(cardinality(p_statuses), 0) = 0
                    or status = any(p_statuses))
               and (p_user_id is null or user_id = p_user_id)
             order by id desc
             limit p_limit) r
      join public.access_users u on u.id = r.user_id;
$$;

create or replace function public.access_count_admins(
    p_admin text, p_enabled_only boolean)
returns integer language sql stable set search_path = '' as $$
    select count(*)::integer from public.access_users
     where role = p_admin and (not p_enabled_only or disabled = 0);
$$;

create or replace function public.access_stats(p_now text, p_admin text)
returns jsonb language sql stable set search_path = '' as $$
    select jsonb_build_object(
        'users',    (select count(*) from public.access_users),
        'admins',   (select count(*) from public.access_users
                      where role = p_admin and disabled = 0),
        'requests', coalesce((select jsonb_object_agg(status, n)
                                from (select status, count(*) as n
                                        from public.access_requests
                                       group by status) s), '{}'::jsonb),
        'live_sessions', (select count(*) from public.access_sessions
                           where revoked_utc is null
                             and expires_utc > p_now collate "C"));
$$;

-- ----------------------------------------------------------- who may use it --

alter table public.access_users      enable row level security;
alter table public.access_requests   enable row level security;
alter table public.access_sessions   enable row level security;
alter table public.access_audit      enable row level security;
alter table public.access_audit_seal enable row level security;

revoke all on public.access_users, public.access_requests, public.access_sessions,
              public.access_audit, public.access_audit_seal
  from anon, authenticated;

grant select, insert, update, delete
   on public.access_users, public.access_requests, public.access_sessions
   to service_role;
grant select, insert, update on public.access_audit_seal to service_role;
-- The audit log: add and read, nothing else, even for the server.
revoke update, delete, truncate on public.access_audit from service_role;
grant select, insert on public.access_audit to service_role;

revoke execute on function
    public.access_note_login_fail(bigint, boolean, text),
    public.access_close_request(bigint, text, text, text, text, text[]),
    public.access_due_requests(text, text, text[]),
    public.access_list_requests(text[], integer, bigint),
    public.access_count_admins(text, boolean),
    public.access_stats(text, text),
    public.access_audit_refuse_change(),
    public.access_audit_check_link()
  from public, anon, authenticated;

grant execute on function
    public.access_note_login_fail(bigint, boolean, text),
    public.access_close_request(bigint, text, text, text, text, text[]),
    public.access_due_requests(text, text, text[]),
    public.access_list_requests(text[], integer, bigint),
    public.access_count_admins(text, boolean),
    public.access_stats(text, text)
  to service_role;

-- Make the Data API see the new tables and functions now, not on its next reload.
notify pgrst, 'reload schema';
