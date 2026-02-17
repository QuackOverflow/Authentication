import { DomainExceptionFilter } from './domain_exception.filter';
import { Test, TestingModule } from '@nestjs/testing';
import {
  UserAlreadyExistsError,
  UserNotFoundError,
  UserWithEmailNotFoundError,
} from '../../domain/exceptions/user.exceptions';
import { HttpStatus, Logger } from '@nestjs/common';
import {
  InvalidCredentialsError,
  PasswordsDontMatchException,
} from '../../domain/exceptions/auth.exceptions';

const mockAppLoggerService = {
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
};
const mockJson = jest.fn();
const mockStatus = jest.fn().mockImplementation(() => ({
  json: mockJson,
}));
const mockGetResponse = jest.fn().mockImplementation(() => ({
  status: mockStatus,
}));

const mockGetRequest = jest.fn().mockImplementation(() => ({
  url: 'fake_url/test',
}));
const mockHttpArgumentsHost = jest.fn().mockImplementation(() => ({
  getResponse: mockGetResponse,
  getRequest: mockGetRequest,
}));

const mockArgumentsHost = {
  switchToHttp: mockHttpArgumentsHost,
  getArgByIndex: jest.fn(),
  getArgs: jest.fn(),
  getType: jest.fn(),
  switchToRpc: jest.fn(),
  switchToWs: jest.fn(),
};

const mockDate = Date.now();

describe('Domain Exception Filter', () => {
  let domainExceptionFilter: DomainExceptionFilter;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.useFakeTimers().setSystemTime(mockDate);
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DomainExceptionFilter,
        { provide: Logger, useValue: mockAppLoggerService },
      ],
    }).compile();

    domainExceptionFilter = module.get<DomainExceptionFilter>(
      DomainExceptionFilter,
    );
  });

  it('Handles UserAlreadyExists errors', () => {
    domainExceptionFilter.catch(
      new UserAlreadyExistsError('test@email.com'),
      mockArgumentsHost,
    );

    expect(mockHttpArgumentsHost).toHaveBeenCalledTimes(1);
    expect(mockHttpArgumentsHost).toHaveBeenCalledWith();
    expect(mockGetResponse).toHaveBeenCalledTimes(1);
    expect(mockGetResponse).toHaveBeenCalledWith();
    expect(mockStatus).toHaveBeenCalledTimes(1);
    expect(mockStatus).toHaveBeenCalledWith(HttpStatus.CONFLICT);
    expect(mockJson).toHaveBeenCalledTimes(1);
    expect(mockJson).toHaveBeenCalledWith({
      message: [`User 'test@email.com' already exists`],
      error: 'USER_ALREADY_EXISTS',
      statusCode: HttpStatus.CONFLICT,
    });
  });

  it('Handles UserNotFound errors', () => {
    domainExceptionFilter.catch(
      new UserNotFoundError('123'),
      mockArgumentsHost,
    );

    expect(mockHttpArgumentsHost).toHaveBeenCalledTimes(1);
    expect(mockHttpArgumentsHost).toHaveBeenCalledWith();
    expect(mockGetResponse).toHaveBeenCalledTimes(1);
    expect(mockGetResponse).toHaveBeenCalledWith();
    expect(mockStatus).toHaveBeenCalledTimes(1);
    expect(mockStatus).toHaveBeenCalledWith(HttpStatus.NOT_FOUND);
    expect(mockJson).toHaveBeenCalledTimes(1);
    expect(mockJson).toHaveBeenCalledWith({
      message: [`User with identifier '123' not found`],
      error: 'USER_NOT_FOUND',
      statusCode: HttpStatus.NOT_FOUND,
    });
  });

  it('Handles UserWithEmailNotFound errors', () => {
    domainExceptionFilter.catch(
      new UserWithEmailNotFoundError('test@email.com'),
      mockArgumentsHost,
    );

    expect(mockHttpArgumentsHost).toHaveBeenCalledTimes(1);
    expect(mockHttpArgumentsHost).toHaveBeenCalledWith();
    expect(mockGetResponse).toHaveBeenCalledTimes(1);
    expect(mockGetResponse).toHaveBeenCalledWith();
    expect(mockStatus).toHaveBeenCalledTimes(1);
    expect(mockStatus).toHaveBeenCalledWith(HttpStatus.NOT_FOUND);
    expect(mockJson).toHaveBeenCalledTimes(1);
    expect(mockJson).toHaveBeenCalledWith({
      message: [`User with email 'test@email.com' not found`],
      error: 'USER_WITH_EMAIL_NOT_FOUND',
      statusCode: HttpStatus.NOT_FOUND,
    });
  });
  it('Handles InvalidCredentials errors', () => {
    domainExceptionFilter.catch(
      new InvalidCredentialsError(),
      mockArgumentsHost,
    );

    expect(mockHttpArgumentsHost).toHaveBeenCalledTimes(1);
    expect(mockHttpArgumentsHost).toHaveBeenCalledWith();
    expect(mockGetResponse).toHaveBeenCalledTimes(1);
    expect(mockGetResponse).toHaveBeenCalledWith();
    expect(mockStatus).toHaveBeenCalledTimes(1);
    expect(mockStatus).toHaveBeenCalledWith(HttpStatus.UNAUTHORIZED);
    expect(mockJson).toHaveBeenCalledTimes(1);
    expect(mockJson).toHaveBeenCalledWith({
      message: [`Invalid email or password`],
      error: 'INVALID_CREDENTIALS',
      statusCode: HttpStatus.UNAUTHORIZED,
    });
  });

  it('Handles PasswordsDontMatch errors', () => {
    domainExceptionFilter.catch(
      new PasswordsDontMatchException(),
      mockArgumentsHost,
    );

    expect(mockHttpArgumentsHost).toHaveBeenCalledTimes(1);
    expect(mockHttpArgumentsHost).toHaveBeenCalledWith();
    expect(mockGetResponse).toHaveBeenCalledTimes(1);
    expect(mockGetResponse).toHaveBeenCalledWith();
    expect(mockStatus).toHaveBeenCalledTimes(1);
    expect(mockStatus).toHaveBeenCalledWith(HttpStatus.UNPROCESSABLE_ENTITY);
    expect(mockJson).toHaveBeenCalledTimes(1);
    expect(mockJson).toHaveBeenCalledWith({
      message: [`Passwords do not match`],
      error: 'PASSWORDS_DONT_MATCH',
      statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
    });
  });

  it('Handles generic errors', () => {
    domainExceptionFilter.catch(new Error('generic error'), mockArgumentsHost);

    expect(mockHttpArgumentsHost).toHaveBeenCalledTimes(1);
    expect(mockHttpArgumentsHost).toHaveBeenCalledWith();
    expect(mockGetResponse).toHaveBeenCalledTimes(1);
    expect(mockGetResponse).toHaveBeenCalledWith();
    expect(mockStatus).toHaveBeenCalledTimes(1);
    expect(mockStatus).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
    expect(mockJson).toHaveBeenCalledTimes(1);
    expect(mockJson).toHaveBeenCalledWith({
      message: [`Internal server error`],
      error: 'INTERNAL_ERROR',
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
    });
  });
});
