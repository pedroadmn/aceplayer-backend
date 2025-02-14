create table if not exists users
(
    id                 varchar(255) not null
        primary key,
    account_locked     boolean      not null,
    created_date       timestamp(6) not null,
    date_of_birth      date,
    email              varchar(255)
        constraint uk_6dotkott2kjsp8vw4d0m25fb7
            unique,
    enabled            boolean      not null,
    firstname          varchar(255),
    last_modified_date timestamp(6),
    lastname           varchar(255),
    password           varchar(255)
);

create table if not exists token
(
    id           integer      not null
        primary key,
    created_at   timestamp(6),
    expires_at   timestamp(6),
    token        varchar(255),
    validated_at timestamp(6),
    user_id      varchar(255) not null
        constraint fkj8rfw4x0wjjyibfqq566j4qng
            references users
);

create table if not exists role
(
    id                 integer      not null
        primary key,
    created_date       timestamp(6) not null,
    last_modified_date timestamp(6),
    name               varchar(255)
        constraint uk_8sewwnpamngi6b1dwaa88askk
            unique
);

create table if not exists users_roles
(
    users_id varchar(255) not null
        constraint fkml90kef4w2jy7oxyqv742tsfc
            references users,
    roles_id integer      not null
        constraint fk15d410tj6juko0sq9k4km60xq
            references role
);