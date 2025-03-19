const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { Application, MailSystem } = require('./main');

// Helper: create Application without triggering file read error.
// Override getNames so that it immediately returns a resolved promise.
function createTestApplicationWithoutFileRead() {
  const originalGetNames = Application.prototype.getNames;
  Application.prototype.getNames = function() {
    return Promise.resolve([this.people, this.selected]);
  };
  const app = new Application();
  // Immediately restore the original getNames for any later use.
  Application.prototype.getNames = originalGetNames;
  return app;
}

// Utility function for a small delay.
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Test: Application.getNames should read names from file.
test('Application.getNames should read names from file', async () => {
  const testData = "Alice\nBob\nCharlie";
  fs.writeFileSync('name_list.txt', testData, 'utf8');

  // Use the real getNames.
  const app = new Application();
  const [people, selected] = await app.getNames();
  assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);

  fs.unlinkSync('name_list.txt');
});

// Test: Application constructor should initialize people and selected.
test('Application constructor should initialize people and selected', async () => {
  const testData = "Alice\nBob";
  fs.writeFileSync('name_list.txt', testData, 'utf8');

  const app = new Application();
  // Wait a bit for the asynchronous constructor to complete.
  await delay(20);
  assert.deepStrictEqual(app.people, ['Alice', 'Bob']);
  assert.deepStrictEqual(app.selected, []);

  fs.unlinkSync('name_list.txt');
});

// Test: getRandomPerson returns a valid name.
test('Application.getRandomPerson should return a valid name', () => {
  const app = createTestApplicationWithoutFileRead();
  app.people = ['Alice', 'Bob', 'Charlie'];

  const originalRandom = Math.random;
  Math.random = () => 0.5; // floor(0.5 * 3) = 1, expecting 'Bob'
  
  const person = app.getRandomPerson();
  assert.strictEqual(person, 'Bob');

  Math.random = originalRandom;
});

// Test: selectNextPerson avoids duplicate selections.
test('Application.selectNextPerson should avoid duplicates', () => {
  const app = createTestApplicationWithoutFileRead();
  app.people = ['Alice', 'Bob', 'Charlie'];
  app.selected = ['Alice'];

  const originalRandom = Math.random;
  // Force Math.random to return a value that selects 'Charlie'
  Math.random = () => 0.8; // floor(0.8 * 3) = 2 -> 'Charlie'
  
  const person = app.selectNextPerson();
  assert.strictEqual(person, 'Charlie');
  assert.strictEqual(app.selected.length, 2);

  Math.random = originalRandom;
});

// Test: selectNextPerson returns null if all persons have been selected.
test('Application.selectNextPerson should return null if all selected', () => {
  const app = createTestApplicationWithoutFileRead();
  app.people = ['Alice', 'Bob'];
  app.selected = ['Alice', 'Bob'];

  const person = app.selectNextPerson();
  assert.strictEqual(person, null);
});

// Test: selectNextPerson loops until a non-duplicate is selected.
test('Application.selectNextPerson should loop until a non-duplicate is selected', () => {
  const app = createTestApplicationWithoutFileRead();
  app.people = ['Alice', 'Bob', 'Charlie'];
  app.selected = ['Alice']; // 'Alice' already selected

  // Override getRandomPerson to simulate a duplicate on first call,
  // then a unique name on the second call.
  let callCount = 0;
  app.getRandomPerson = function() {
    callCount++;
    if (callCount === 1) {
      return 'Alice'; // duplicate value
    } else {
      return 'Bob'; // new value
    }
  };

  const selectedPerson = app.selectNextPerson();
  assert.strictEqual(selectedPerson, 'Bob');
  assert.strictEqual(callCount, 2); // getRandomPerson should be called twice
});

// Test: MailSystem.write generates the correct mail content.
test('MailSystem.write should generate correct mail content', () => {
  const mailSystem = new MailSystem();
  const content = mailSystem.write('Alice');
  assert.strictEqual(content, 'Congrats, Alice!');
});

// Test: MailSystem.send returns true when Math.random is high.
test('MailSystem.send should return true when Math.random is high', () => {
  const mailSystem = new MailSystem();
  const originalRandom = Math.random;
  Math.random = () => 0.9; // Simulate success
  
  const result = mailSystem.send('Alice', 'Congrats, Alice!');
  assert.strictEqual(result, true);
  
  Math.random = originalRandom;
});

// Test: MailSystem.send returns false when Math.random is low.
test('MailSystem.send should return false when Math.random is low', () => {
  const mailSystem = new MailSystem();
  const originalRandom = Math.random;
  Math.random = () => 0.1; // Simulate failure
  
  const result = mailSystem.send('Alice', 'Congrats, Alice!');
  assert.strictEqual(result, false);
  
  Math.random = originalRandom;
});

// Test: notifySelected calls write and send for each selected person.
test('Application.notifySelected should call write and send for each person', () => {
  const app = createTestApplicationWithoutFileRead();
  app.selected = ['Alice', 'Bob'];

  let writeCalls = [];
  let sendCalls = [];
  
  const originalWrite = app.mailSystem.write;
  const originalSend = app.mailSystem.send;

  // Override write and send to record calls.
  app.mailSystem.write = function(name) {
    writeCalls.push(name);
    return 'Congrats!';
  };

  app.mailSystem.send = function(name, context) {
    sendCalls.push({ name, context });
    return true;
  };

  app.notifySelected();

  assert.deepStrictEqual(writeCalls, ['Alice', 'Bob']);
  assert.strictEqual(sendCalls.length, 2);
  assert.deepStrictEqual(sendCalls[0], { name: 'Alice', context: 'Congrats!' });
  assert.deepStrictEqual(sendCalls[1], { name: 'Bob', context: 'Congrats!' });

  app.mailSystem.write = originalWrite;
  app.mailSystem.send = originalSend;
});
