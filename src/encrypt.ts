import * as crypto from 'crypto';
import * as debugModule from 'debug';
import { promisify } from 'util';

const debug = debugModule('loopback:mixin:crypto');
const randomBytesAsync = promisify(crypto.randomBytes);
const DYNAMIC_CONFIG_PARAM = /\$\{(\w+)\}$/;

module.exports = (Model: any, options?: any) => {
  options = options || {};
  const { properties } = options;

  const hiddenIV = options.hiddenIV !== false;
  const propertyNameIV = options.propertyNameIV || 'iv';

  Model.defineProperty(propertyNameIV, { type: Buffer, required: true });

  if (hiddenIV) {
    const hiddenProperties = Model._getHiddenProperties() || [];
    hiddenProperties.push(propertyNameIV);
    Model.definition.settings.hiddenProperties = hiddenProperties;
  }

  const password = getConfigVariable(options.password);

  if (password === undefined) {
    throw new Error('Set a valid password');
  }

  const algorithm = options.algorithm || 'aes-256-cbc';

  Model._encryptProperties =
    Array.isArray(properties) && properties.length > 0
      ? properties
      : getEncryptedProperties();

  if (Model._encryptProperties.length === 0) {
    throw new Error('Encrypt properties not found.');
  }

  Model.getInitializationVectorName = () => {
    return propertyNameIV;
  };

  Model.observe('before save', async (ctx: any) => {
    const { isNewInstance, instance } = ctx;
    if (isNewInstance) {
      const iv = Model.getInitializationVectorName();
      instance[iv] = await randomBytesAsync(16);
    }

    return;
  });

  Model.observe('persist', async (ctx: any) => {
    const { data } = ctx;

    const iv = Model.getInitializationVectorName();

    for (const property of Model._encryptProperties) {
      if (data[property] !== undefined) {
        const value = ctx.data[property];
        ctx.data[property] = Model._encrypt(value, data[iv]);
      }
    }

    return;
  });

  Model.observe('loaded', async (ctx: any) => {
    // tslint:disable-next-line:no-shadowed-variable
    const { data, options } = ctx;
    if (!!options.skipDecrypt) {
      return;
    }

    const iv = Model.getInitializationVectorName();

    for (const property of Model._encryptProperties) {
      if (data[property] !== undefined) {
        const value = ctx.data[property];
        ctx.data[property] = Model._decrypt(
          Buffer.from(value, 'hex'),
          Buffer.from(data[iv])
        );
      }
    }

    return;
  });

  Model._encrypt = (text: string, iv: Buffer): string => {
    const data = Buffer.from(text);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(password), iv);
    let crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
  };

  Model._decrypt = (text: Buffer, iv: Buffer): string => {
    const decipher = crypto.createDecipheriv(
      algorithm,
      Buffer.from(password),
      iv
    );
    let decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  };

  function getEncryptedProperties(): string[] {
    const encryptedProperties = [];
    // tslint:disable-next-line:no-shadowed-variable
    const { properties } = Model.definition;
    for (const [key, settings] of Object.entries(properties)) {
      const { encrypted } = settings as any;
      if (encrypted) {
        encryptedProperties.push(key);
      }
    }

    return encryptedProperties;
  }

  function getConfigVariable(param: string) {
    let configVariable: any = param;
    const match = configVariable.match(DYNAMIC_CONFIG_PARAM);
    if (match) {
      const varName = match[1];
      if (process.env[varName] !== undefined) {
        debug(
          'Dynamic Configuration: Resolved via process.env: %s as %s',
          process.env[varName],
          param
        );
        configVariable = process.env[varName];
      } else {
        // previously it returns the original string such as "${restApiRoot}"
        // it will now return `undefined`, for the use case of
        // dynamic datasources url:`undefined` to fallback to other parameters
        configVariable = undefined;
        debug(
          'Dynamic Configuration: Cannot resolve variable for `%s`, ' +
            'returned as %s',
          varName,
          configVariable
        );
      }
    }
    return configVariable;
  }
};
