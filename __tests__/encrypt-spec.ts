// tslint:disable-next-line:no-implicit-dependencies
import { DataSource, ModelBuilder } from 'loopback-datasource-juggler';

import * as encrypt from '../src/encrypt';

describe('Encrypt mixin', () => {
  let User: any;
  let UserWithIV: any;
  let UserWithMixinProperties: any;
  let memory: any;

  beforeAll(() => {
    const modelBuilder = new ModelBuilder() as any;
    const mixins: any = modelBuilder.mixins;

    mixins.define('Encrypt', encrypt);

    memory = new DataSource('db', { connector: 'memory' }, modelBuilder);

    User = memory.createModel(
      'User',
      {
        email: { type: 'string', required: true, encrypted: true },
        firstName: { type: 'string', encrypted: true },
        language: 'string',
        lastName: { type: 'string', encrypted: true },
      },
      {
        mixins: {
          Encrypt: {
            password: 'mKp82LCwZ(2`Q*8E<as>Pq{%,gNG{:Hh',
          },
        },
      }
    );

    UserWithIV = memory.createModel(
      'UserCustomIV',
      {
        email: { type: 'string', required: true, encrypted: true },
        firstName: { type: 'string', encrypted: true },
        language: 'string',
        lastName: { type: 'string', encrypted: true },
      },
      {
        mixins: {
          Encrypt: {
            hiddenIV: false,
            password: 'mKp82LCwZ(2`Q*8E<as>Pq{%,gNG{:Hh',
            propertyNameIV: 'vector',
          },
        },
      }
    );

    UserWithMixinProperties = memory.createModel(
      'UserWithMixinProperties',
      {
        email: { type: 'string', required: true },
        firstName: { type: 'string' },
        language: 'string',
        lastName: { type: 'string' },
      },
      {
        mixins: {
          Encrypt: {
            password: 'mKp82LCwZ(2`Q*8E<as>Pq{%,gNG{:Hh',
            properties: ['email', 'firstName', 'lastName'],
          },
        },
      }
    );
  });

  afterEach(async () => {
    await User.destroyAll();
    await UserWithIV.destroyAll();
    await UserWithMixinProperties.destroyAll();
  });

  test('encrypt properties', async () => {
    const data = { email: 'test@test.it' };
    const user = await User.create(data);
    expect(user.id).toBeDefined();
    expect(user.email).toEqual(data.email);
    const instance = await User.findById(user.id, undefined, {
      skipDecrypt: true,
    });
    expect(instance).toBeTruthy();
    expect(instance.id).toEqual(user.id);
    expect(instance.email).not.toEqual(data.email);
    const emailEncrypted = User._encrypt(data.email, Buffer.from(instance.iv));
    expect(emailEncrypted).toEqual(instance.email);
  });

  test('decrypt properties', async () => {
    const data = { email: 'test@test.it' };
    const user = await User.create(data);
    expect(user.id).toBeDefined();
    expect(user.email).toEqual(data.email);
    const instance = await User.findById(user.id);
    expect(instance).toBeTruthy();
    expect(instance.id).toEqual(user.id);
    expect(instance.email).toEqual(data.email);
  });

  describe('initialization vector property', () => {
    test('default configuration hidden initialization vector', async () => {
      const data = { email: 'test@test.it' };
      const user = await User.create(data);
      expect(user.id).toBeDefined();
      expect(user.email).toEqual(data.email);
      let instance = await User.findById(user.id, undefined, {
        skipDecrypt: true,
      });
      expect(instance).toBeTruthy();
      expect(instance.id).toEqual(user.id);
      expect(instance.email).not.toEqual(data.email);
      instance = instance.toJSON();
      expect(instance.iv).toBeUndefined();
    });

    test('return initialization vector', async () => {
      const data = { email: 'test@test.it' };
      const user = await UserWithIV.create(data);
      expect(user.id).toBeDefined();
      expect(user.email).toEqual(data.email);
      let instance = await UserWithIV.findById(user.id);
      instance = instance.toJSON();
      expect(instance).toBeTruthy();
      expect(instance.id).toEqual(user.id);
      expect(instance.email).toEqual(data.email);
      expect(instance.vector).toBeTruthy();
    });
  });

  describe('Configuration mixin', () => {
    let UserDynamicPassowrd: any;

    test('not set dynamic password should report error', async () => {
      delete process.env.USER_DYNAMIC_PASSWORD_CRYPTO;
      expect(() => {
        memory.createModel(
          'UserDynamicPassowrd',
          {
            email: { type: 'string', required: true, encrypted: true },
            firstName: { type: 'string', encrypted: true },
            language: 'string',
            lastName: { type: 'string', encrypted: true },
          },
          {
            mixins: {
              Encrypt: {
                hiddenIV: false,
                // tslint:disable-next-line:no-invalid-template-strings
                password: '${USER_DYNAMIC_PASSWORD_CRYPTO}',
                propertyNameIV: 'vector',
              },
            },
          }
        );
      }).toThrowError();
    });

    test('Configurable password', async () => {
      process.env.USER_DYNAMIC_PASSWORD_CRYPTO =
        'VQs6as6fCGVYsGa7vqHEr2PqMxUAFMyQ';
      UserDynamicPassowrd = memory.createModel(
        'UserDynamicPassowrd',
        {
          email: { type: 'string', required: true, encrypted: true },
          firstName: { type: 'string', encrypted: true },
          language: 'string',
          lastName: { type: 'string', encrypted: true },
        },
        {
          mixins: {
            Encrypt: {
              hiddenIV: false,
              // tslint:disable-next-line:no-invalid-template-strings
              password: '${USER_DYNAMIC_PASSWORD_CRYPTO}',
              propertyNameIV: 'vector',
            },
          },
        }
      );

      const data = { email: 'test@test.it' };
      const user = await UserDynamicPassowrd.create(data);
      expect(user.id).toBeDefined();
      expect(user.email).toEqual(data.email);
      let instance = await UserDynamicPassowrd.findById(user.id);
      instance = instance.toJSON();
      expect(instance).toBeTruthy();
      expect(instance.id).toEqual(user.id);
      expect(instance.email).toEqual(data.email);
      expect(instance.vector).toBeTruthy();
    });

    test('encrypt properties configured in mixin options', async () => {
      const data = {
        email: 'test@test.it',
        firstName: 'Henry',
        lastName: 'Ford',
      };
      const user = await UserWithMixinProperties.create(data);
      expect(user.id).toBeDefined();
      expect(user).toMatchObject(data);
      const instance = await UserWithMixinProperties.findById(
        user.id,
        undefined,
        { skipDecrypt: true }
      );
      expect(instance).toBeTruthy();
      expect(instance.id).toEqual(user.id);
      expect(instance.email).not.toEqual(data.email);
      expect(instance.firstName).not.toEqual(data.firstName);
      expect(instance.lastName).not.toEqual(data.lastName);
      const encryptedData = {
        email: User._encrypt(data.email, Buffer.from(instance.iv)),
        firstName: User._encrypt(data.firstName, Buffer.from(instance.iv)),
        lastName: User._encrypt(data.lastName, Buffer.from(instance.iv)),
      };

      expect(instance).toMatchObject(encryptedData);
    });
  });
});
