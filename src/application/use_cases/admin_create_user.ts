import { Inject, Injectable } from '@nestjs/common';
import { User } from 'src/domain/entities/user.entity';
import { UserFactory } from 'src/domain/entities/user.factory';
import { UserAlreadyExistsError } from 'src/domain/exceptions/user.exceptions';
import { ICryptoGateway } from '../interfaces/crypto_gateway';
import { IUseCase } from '../interfaces/use_case';
import { IUserRepository } from '../interfaces/user_repository';
import { AdminCreateUserRequest } from '../dtos/admin_create_user_request';

@Injectable()
export class AdminCreateUserUseCase
  implements IUseCase<AdminCreateUserRequest, User>
{
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: IUserRepository,

    @Inject('CryptoGateway')
    private readonly cryptoGateway: ICryptoGateway,
  ) {}

  async execute(input: AdminCreateUserRequest): Promise<User> {
    const { name, email, password } = input;

    // Check if email already exists
    const existingByEmail = await this.userRepository.findByEmail(email);
    if (existingByEmail) {
      throw new UserAlreadyExistsError(email);
    }

    // Check if username already exists
    const existingByName = await this.userRepository.findByName(name);
    if (existingByName) {
      throw new UserAlreadyExistsError(name);
    }

    // Hash the password
    const hashedPassword = await this.cryptoGateway.hash(password);

    // Create user entity
    const user = UserFactory.create({ name, email, password: hashedPassword });

    // Save user to repository
    await this.userRepository.save(user);

    return user;
  }
}
