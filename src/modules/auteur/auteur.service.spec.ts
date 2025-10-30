import { Test, TestingModule } from '@nestjs/testing';
import { AuteurService } from './auteur.service';

describe('AuteurService', () => {
  let service: AuteurService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuteurService],
    }).compile();

    service = module.get<AuteurService>(AuteurService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
