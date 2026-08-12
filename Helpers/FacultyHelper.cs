namespace StudentProjectPapers.Helpers
{
    public static class FacultyHelper
    {
        /// <summary>
        /// Returns the set of faculties a user with the given home faculty can access.
        /// BIT and BCS share one project/document pool; all other faculties see only
        /// their own department.
        /// </summary>
        public static string[] GetManagedFaculties(string? faculty)
        {
            if (string.IsNullOrEmpty(faculty))
                return Array.Empty<string>();

            return faculty switch
            {
                "BIT" => new[] { "BIT", "BCS" },
                "BCS" => new[] { "BIT", "BCS" },
                _ => new[] { faculty }
            };
        }
    }
}
