import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyEmailDto {
  @ApiProperty({
      example: '123',
      description: 'Id of the user',
    })
  @IsString() userId: string;

  @ApiProperty({
      example: '123456',
      description: 'Otp code received in mail',
    })
  @IsString() code: string;
}
