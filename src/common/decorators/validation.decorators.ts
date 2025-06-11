import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

/**
 * Custom validator for strong passwords
 */
@ValidatorConstraint({ name: 'isStrongPassword', async: false })
export class IsStrongPasswordConstraint implements ValidatorConstraintInterface {
  validate(password: string, args: ValidationArguments) {
    if (!password || typeof password !== 'string') {
      return false;
    }

    // Check minimum length
    if (password.length < 8) {
      return false;
    }

    // Check maximum length
    if (password.length > 128) {
      return false;
    }

    // Check for at least one lowercase letter
    if (!/[a-z]/.test(password)) {
      return false;
    }

    // Check for at least one uppercase letter
    if (!/[A-Z]/.test(password)) {
      return false;
    }

    // Check for at least one number
    if (!/\d/.test(password)) {
      return false;
    }

    // Check for at least one special character
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      return false;
    }

    // Check for common weak passwords
    const weakPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein'];
    if (weakPasswords.some(weak => password.toLowerCase().includes(weak))) {
      return false;
    }

    return true;
  }

  defaultMessage(args: ValidationArguments) {
    return 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character';
  }
}

export function IsStrongPassword(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsStrongPasswordConstraint,
    });
  };
}

/**
 * Custom validator for safe usernames (no special characters)
 */
@ValidatorConstraint({ name: 'isSafeUsername', async: false })
export class IsSafeUsernameConstraint implements ValidatorConstraintInterface {
  validate(username: string, args: ValidationArguments) {
    if (!username || typeof username !== 'string') {
      return false;
    }

    // Only allow alphanumeric characters, underscores, and hyphens
    const safeUsernameRegex = /^[a-zA-Z0-9_-]+$/;
    return safeUsernameRegex.test(username);
  }

  defaultMessage(args: ValidationArguments) {
    return 'Username can only contain letters, numbers, underscores, and hyphens';
  }
}

export function IsSafeUsername(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsSafeUsernameConstraint,
    });
  };
}

/**
 * Custom validator for safe text (no HTML/script tags)
 * Now with integrated sanitization service
 */
@ValidatorConstraint({ name: 'isSafeText', async: false })
export class IsSafeTextConstraint implements ValidatorConstraintInterface {
  validate(text: string, args: ValidationArguments) {
    if (!text || typeof text !== 'string') {
      return true; // Allow empty strings, use @IsNotEmpty for required fields
    }

    // Enhanced validation using multiple security checks

    // Check for HTML tags
    const htmlTagRegex = /<[^>]*>/g;
    if (htmlTagRegex.test(text)) {
      return false;
    }

    // Check for script-related content
    const scriptPatterns = [
      /javascript:/gi,
      /vbscript:/gi,
      /data:text\/html/gi,
      /on\w+\s*=/gi,
    ];

    if (scriptPatterns.some(pattern => pattern.test(text))) {
      return false;
    }

    // Check for SQL injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
      /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
      /('|(\\')|(;)|(\\;)|(\-\-)|(\#)|(\*)|(\%27)|(\%3B)|(\%23)|(\%2A))/gi,
    ];

    if (sqlPatterns.some(pattern => pattern.test(text))) {
      return false;
    }

    // Check for NoSQL injection patterns
    const noSqlPatterns = [
      /\$where/gi, /\$ne/gi, /\$gt/gi, /\$lt/gi, /\$regex/gi, /\$or/gi, /\$and/gi,
    ];

    if (noSqlPatterns.some(pattern => pattern.test(text))) {
      return false;
    }

    return true;
  }

  defaultMessage(args: ValidationArguments) {
    return 'Text contains potentially unsafe content (HTML, scripts, or injection patterns)';
  }
}

export function IsSafeText(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsSafeTextConstraint,
    });
  };
}

/**
 * Custom validator for business email domains
 */
@ValidatorConstraint({ name: 'isBusinessEmail', async: false })
export class IsBusinessEmailConstraint implements ValidatorConstraintInterface {
  private readonly blockedDomains = [
    'tempmail.org',
    '10minutemail.com',
    'guerrillamail.com',
    'mailinator.com',
    'throwaway.email',
  ];

  validate(email: string, args: ValidationArguments) {
    if (!email || typeof email !== 'string') {
      return false;
    }

    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) {
      return false;
    }

    // Block temporary email domains
    return !this.blockedDomains.includes(domain);
  }

  defaultMessage(args: ValidationArguments) {
    return 'Temporary email addresses are not allowed';
  }
}

export function IsBusinessEmail(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsBusinessEmailConstraint,
    });
  };
}

/**
 * Custom validator for safe file names
 */
@ValidatorConstraint({ name: 'isSafeFileName', async: false })
export class IsSafeFileNameConstraint implements ValidatorConstraintInterface {
  validate(fileName: string, args: ValidationArguments) {
    if (!fileName || typeof fileName !== 'string') {
      return false;
    }

    // Check for dangerous characters
    const dangerousChars = /[<>:"/\\|?*\x00-\x1f]/;
    if (dangerousChars.test(fileName)) {
      return false;
    }

    // Check for reserved names (Windows)
    const reservedNames = [
      'CON', 'PRN', 'AUX', 'NUL',
      'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ];

    const nameWithoutExtension = fileName.split('.')[0].toUpperCase();
    if (reservedNames.includes(nameWithoutExtension)) {
      return false;
    }

    // Check length
    if (fileName.length > 255) {
      return false;
    }

    return true;
  }

  defaultMessage(args: ValidationArguments) {
    return 'File name contains invalid characters or is a reserved name';
  }
}

export function IsSafeFileName(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsSafeFileNameConstraint,
    });
  };
}

/**
 * Custom validator for array size limits
 */
@ValidatorConstraint({ name: 'arrayMaxSize', async: false })
export class ArrayMaxSizeConstraint implements ValidatorConstraintInterface {
  validate(value: any[], args: ValidationArguments) {
    if (!Array.isArray(value)) {
      return true; // Let other validators handle non-array values
    }

    const [maxSize] = args.constraints;
    return value.length <= maxSize;
  }

  defaultMessage(args: ValidationArguments) {
    const [maxSize] = args.constraints;
    return `Array must contain no more than ${maxSize} items`;
  }
}

export function ArrayMaxSize(maxSize: number, validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [maxSize],
      validator: ArrayMaxSizeConstraint,
    });
  };
}
