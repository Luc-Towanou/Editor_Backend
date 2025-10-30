import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    example: 'john@example.com',
    description: 'Your mail adress',
  })
  @IsEmail() email: string;

  @ApiProperty({
      example: '@MotDePasse123!',
      description: 'Your saved password (min. 8 chars)',
    })
  @MinLength(8)
  @IsNotEmpty() mot_de_passe: string;

  @ApiProperty({
      example: '',
      description: 'Connected device info',
    })
  deviceInfo?: string;
}
