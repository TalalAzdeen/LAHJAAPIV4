using AutoGenerator;
using AutoGenerator.Helper.Translation;
using LAHJAAPI.Models;
using AutoGenerator.Config;
using System;

namespace V1.DyModels.Dto.Build.ResponseFilters
{
    public class CategoryModelResponseFilterBuildDto : ITBuildDto
    {
        /// <summary>
        /// Id property for DTO.
        /// </summary>
        public String? Id { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }

        [FilterLGEnabled]
        public string? Lg { get; set; }
    }
}