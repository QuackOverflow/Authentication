import { DomainException } from './domain_exception';

export class UserAlreadyExistsError extends DomainException {
  constructor(identifier: string) {
    super(`User '${identifier}' already exists`);
    this.name = 'UserAlreadyExistsError';
  }
}

export class UserNotFoundError extends DomainException {
  constructor(identifier: string) {
    super(`User with identifier '${identifier}' not found`);
    this.name = 'UserNotFoundError';
  }
}

export class UserWithEmailNotFoundError extends DomainException {
  constructor(email: string) {
    super(`User with email '${email}' not found`);
    this.name = 'UserWithEmailNotFoundError';
  }
}
