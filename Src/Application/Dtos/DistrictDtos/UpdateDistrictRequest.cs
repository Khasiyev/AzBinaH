using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Dtos.DistrictDtos;

public class UpdateDistrictRequest
{
    public int Id { get; set; }
    public string Name { get; set; } = null!;
    public int CityId { get; set; }
}
