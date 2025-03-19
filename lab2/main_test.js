const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { Application, MailSystem } = require('./main');

// Utility function to delay a bit
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Test Application.getNames by writing a temporary file 'name_list.txt'
test('Application.getNames should read names from file', async () => {
  const testData = "Alice\nBob\nCharlie";
  fs.writeFileSync('name_list.txt', testData, 'utf8');

  const app = new Application();
  const [people, selected] = await app.getNames();
  assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);

  // Clean up the temporary file
  fs.unlinkSync('name_list.txt');
});

// Test that the Application constructor initializes people and selected correctly.
test('Application constructor should initialize people and selected', async () => {
  const testData = "Alice\nBob";
  fs.writeFileSync('name_list.txt', testData, 'utf8');

  const app = new Application();
  // Wait a bit for the asynchronous constructor call to complete.
  await delay(20);
  assert.deepStrictEqual(app.people, ['Alice', 'Bob']);
  assert.deepStrictEqual(app.selected, []);

  fs.unlinkSync('name_list.txt');
});

// Test Application.getRandomPerson returns a valid name.
test('Application.getRandomPerson should return a valid name', () => {
  const app = new Application();
  app.people = ['Alice', 'Bob', 'Charlie'];

  const originalRandom = Math.random;
  Math.random = () => 0.5; // For 3 items, floor(0.5 * 3) = 1, expecting 'Bob'
  
  const person = app.getRandomPerson();
  assert.strictEqual(person, 'Bob');

  Math.random = originalRandom;
});

// Test Application.selectNextPerson avoids duplicate selections.
test('Application.selectNextPerson should avoid duplicates', () => {
  const app = new Application();
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

// Test Application.selectNextPerson returns null if all persons have been selected.
test('Application.selectNextPerson should return null if all selected', () => {
  const app = new Application();
  app.people = ['Alice', 'Bob'];
  app.selected = ['Alice', 'Bob'];

  const person = app.selectNextPerson();
  assert.strictEqual(person, null);
});

// Test MailSystem.write generates the correct mail content.
test('MailSystem.write should generate correct mail content', () => {
  const mailSystem = new MailSystem();
  const content = mailSystem.write('Alice');
  assert.strictEqual(content, 'Congrats, Alice!');
});

// Test MailSystem.send returns true when Math.random is high.
test('MailSystem.send should return true when Math.random is high', () => {
  const mailSystem = new MailSystem();
  const originalRandom = Math.random;
  Math.random = () => 0.9; // Simulate success
  
  const result = mailSystem.send('Alice', 'Congrats, Alice!');
  assert.strictEqual(result, true);
  
  Math.random = originalRandom;
});

// Test MailSystem.send returns false when Math.random is low.
test('MailSystem.send should return false when Math.random is low', () => {
  const mailSystem = new MailSystem();
  const originalRandom = Math.random;
  Math.random = () => 0.1; // Simulate failure
  
  const result = mailSystem.send('Alice', 'Congrats, Alice!');
  assert.strictEqual(result, false);
  
  Math.random = originalRandom;
});

// Test Application.notifySelected calls write and send for each person.
test('Application.notifySelected should call write and send for each person', () => {
  const app = new Application();
  app.selected = ['Alice', 'Bob'];

  // Create arrays to record calls.
  let writeCalls = [];
  let sendCalls = [];
  
  // Backup original methods.
  const originalWrite = app.mailSystem.write;
  const originalSend = app.mailSystem.send;

  // Override write and send.
  app.mailSystem.write = function(name) {
    writeCalls.push(name);
    return 'Congrats!';
  };

  app.mailSystem.send = function(name, context) {
    sendCalls.push({ name, context });
    return true;
  };

  app.notifySelected();

  // Verify that write was called for each selected person.
  assert.deepStrictEqual(writeCalls, ['Alice', 'Bob']);
  // Verify that send was called with the correct parameters.
  assert.strictEqual(sendCalls.length, 2);
  assert.deepStrictEqual(sendCalls[0], { name: 'Alice', context: 'Congrats!' });
  assert.deepStrictEqual(sendCalls[1], { name: 'Bob', context: 'Congrats!' });

  // Restore original methods.
  app.mailSystem.write = originalWrite;
  app.mailSystem.send = originalSend;
});
