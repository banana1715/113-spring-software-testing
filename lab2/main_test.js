const test = require('node:test');
const assert = require('assert');
const sinon = require('sinon');
const fs = require('fs').promises;
const { Application, MailSystem } = require('./main');

test('MailSystem - write should return correct message', () => {
    const mailSystem = new MailSystem();
    const spy = sinon.spy(mailSystem, 'write');

    const name = 'Alice';
    const expectedMessage = `Congrats, ${name}!`;
    const result = mailSystem.write(name);

    assert.strictEqual(result, expectedMessage);
    assert.strictEqual(spy.calledOnce, true);
    assert.strictEqual(spy.calledWith(name), true);

    spy.restore();
});

test('MailSystem - send should return boolean', () => {
    const mailSystem = new MailSystem();
    const stub = sinon.stub(mailSystem, 'send').returns(true); // Force success

    const success = mailSystem.send('Alice', 'Test Message');

    assert.strictEqual(success, true);
    assert.strictEqual(stub.calledOnce, true);

    stub.restore();
});

test('MailSystem - sendWithRetry should retry on failure', async () => {
    const mailSystem = new MailSystem();
    const sendStub = sinon.stub(mailSystem, 'send').returns(false); // Always fail

    const success = await mailSystem.sendWithRetry('Alice', 'Test Message', 3);

    assert.strictEqual(success, false);
    assert.strictEqual(sendStub.callCount, 3); // Should retry 3 times

    sendStub.restore();
});

test('Application - getNames should read and split names correctly', async () => {
    const fakeFileData = 'Alice\nBob\nCharlie';
    const readStub = sinon.stub(fs, 'readFile').resolves(fakeFileData);

    const app = new Application();
    await app.init();

    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);

    assert.strictEqual(readStub.calledOnce, true);
    readStub.restore();
});

test('Application - getNames should handle empty file gracefully', async () => {
    const readStub = sinon.stub(fs, 'readFile').resolves('');

    const app = new Application();
    await app.init();

    assert.deepStrictEqual(app.people, []);
    assert.deepStrictEqual(app.selected, []);

    assert.strictEqual(readStub.calledOnce, true);
    readStub.restore();
});

test('Application - selectNextPerson should not select the same person twice', async () => {
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];

    const spy = sinon.spy(app, 'selectNextPerson');

    const selected = new Set();
    for (let i = 0; i < app.people.length; i++) {
        const person = app.selectNextPerson();
        assert.strictEqual(selected.has(person), false);
        selected.add(person);
    }

    assert.strictEqual(selected.size, 3);
    assert.strictEqual(app.selectNextPerson(), null);
    assert.strictEqual(spy.callCount, 4); // Called one extra time when all are selected

    spy.restore();
});

test('Application - notifySelected should call MailSystem correctly', async () => {
    const app = new Application();
    app.mailSystem = new MailSystem();

    const writeSpy = sinon.spy(app.mailSystem, 'write');
    const sendMock = sinon.mock(app.mailSystem);
    sendMock.expects('sendWithRetry').twice().resolves(true);

    app.selected = ['Alice', 'Bob'];
    await app.notifySelected();

    assert.strictEqual(writeSpy.calledTwice, true);
    sendMock.verify();

    writeSpy.restore();
    sendMock.restore();
});
