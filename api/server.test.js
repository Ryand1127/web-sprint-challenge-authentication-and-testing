const db = require('../data/dbconfig');
const server = require('./server');
const request = require('supertest')

// Write your tests here
test('sanity', () => {
  expect(true).toBe(false)
})

beforeAll(async () => {
  await db.migrate.rollback()
  await db.migrate.latest()
})
beforeEach(async() => {
  await db('users').truncate()
})
afterAll(async () => {
  await db.destroy()
})

