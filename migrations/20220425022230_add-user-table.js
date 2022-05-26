/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  /*
    // equivalente usando SQL
    knex.schema.raw(`
      CREATE TABLE users (
        id          INT           PRIMARY KEY AUTOINCREMENT,
        username    VARCHAR(255)  NOT NULL UNIQUE,
        password    VARCHAR(255)  NOT NULL,
        first_name  VARCHAR(255)  NOT NULL,
        last_name   VARCHAR(255)  NOT NULL
      )
    `)
  */
  return knex.schema
    .createTable('users', (table) => {
       table.increments('id').primary()
       table.string('username', 255).notNullable().unique()
      table.string('password', 255).notNullable()
       table.string('first_name', 255).notNullable()
       table.string('last_name', 255).notNullable()
    })
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTable('users')
};
