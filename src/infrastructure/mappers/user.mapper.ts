import { User } from 'src/domain/entities/user.entity';
import { UserEntity } from '../database/entities/user.entity';
import { UserFactory } from 'src/domain/entities/user.factory';

export class UserMapper {
  static toDomain(userEntity: UserEntity): User {
    return UserFactory.reconstitute({
      id: userEntity.id,
      name: userEntity.name,
      email: userEntity.email,
      password: userEntity.password,
      role: userEntity.role,
    });
  }

  static toPersistence(user: User): UserEntity {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      password: user.password,
      role: user.role,
    };
  }

  static toDomainList(userEntities: UserEntity[]): User[] {
    // eslint-disable-next-line @typescript-eslint/unbound-method
    return userEntities.map(UserMapper.toDomain);
  }
}
