import { Test, TestingModule } from '@nestjs/testing';
import { MaisonEditionService } from './maison-edition.service';

describe('MaisonEditionService', () => {
  let service: MaisonEditionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [MaisonEditionService],
    }).compile();

    service = module.get<MaisonEditionService>(MaisonEditionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
