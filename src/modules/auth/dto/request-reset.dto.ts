import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class RequestResetDto { 
    @ApiProperty({
    example: 'john@example.com',
    description: 'Your mail adress',
  })
    @IsEmail() email: string; 
}
