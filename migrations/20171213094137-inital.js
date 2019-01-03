'use strict';

var dbm;
var type;
var seed;

exports.setup = function(options, seedLink) {
    dbm = options.dbmigrate;
    type = dbm.dataType;
    seed = seedLink;
};

exports.up = function (db) {
    db.createTable('users', {
        uuid: { type: 'string', length: 36, primaryKey: true, unique: true, notNull: true },
        first_name: { type: 'string', length: 45, notNull: true },
        last_name: { type: 'string', length: 45, notNull: true },
        email: { type: 'string', length: 45, unique: true, notNull:true },
        password: { type: 'string', length: 64, notNull: true }
    });
    db.createTable('jwt_tokens', {
        token: { type: 'text', notNull: true },
        users_uuid: { type: 'string', length: 36, notNull: true, foreignKey: {
            name: 'jwt_tokens_users_uuid_fk',
            table: 'users',
            rules: {
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE'
            },
            mapping: 'uuid'
        }}
    });
    db.createTable('devices', {
        id_devices: { type: 'int', unique: true, notNull: true, autoIncrement: true, primaryKey: true },
        devices_name: { type: 'string', length: 45, notNull: true },
	is_deleted: { type: 'boolean', notNull: true, defaultValue: false },
        users_uuid: { type: 'string', length: 36, notNull: true, foreignKey: {
            name: 'devices_users_uuid_fk',
            table: 'users',
            rules: {
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE'
            },
            mapping: 'uuid'
        }}        
    });
    db.createTable('collections', {
        id_collections: { type: 'int', unique: true, notNull: true, autoIncrement: true, primaryKey: true },
        collections_name: { type: 'string', length: 45, notNull: true },
        users_uuid: { type: 'string', length: 36, notNull: true, foreignKey: {
            name: 'groups_users_uuid_fk',
            table: 'users',
            rules: {
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE'
            },
            mapping: 'uuid'
        }}        
    });
    return db.createTable('devices_has_collections', {
        id_devices: { type: 'int', notNull: true, foreignKey: {
            name: 'devices_has_collections_id_devices_fk',
            table: 'devices',
            rules: {
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE'
            },
            mapping: 'id_devices'
        }},
        id_collections: { type: 'int', notNull: true, foreignKey: {
            name: 'devices_has_collections_id_collections_fk',
            table: 'collections',
            rules: {
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE'
            },
            mapping: 'id_collections'
        }}       
    });
};

exports.down = function (db) {
    db.dropTable('users');
    db.dropTable('jwt_tokens');
    db.dropTable('devices');
    db.dropTable('collections');
    return db.dropTable('devices_has_collections');
};

exports._meta = {
    "version": 1
};
