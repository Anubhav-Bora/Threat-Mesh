interface LogoProps {
  compact?: boolean;
}

export function Logo({ compact = false }: LogoProps) {
  return (
    <div className="brand" aria-label="ThreatMesh">
      <svg className="brand__mark" viewBox="0 0 44 44" aria-hidden="true">
        <path
          d="M22 2.8 39 12.4v19.2L22 41.2 5 31.6V12.4L22 2.8Z"
          className="brand__hex"
        />
        <path
          d="m14 16.8 8-4.5 8 4.5v9.1L22 31l-8-5.1v-9.1Z"
          className="brand__core"
        />
        <circle cx="22" cy="22" r="2.8" />
        <path
          d="M22 19.2v-7M19.5 23.6l-6 3.4m11-3.4 6 3.4"
          className="brand__links"
        />
      </svg>
      {!compact && (
        <span className="brand__wordmark">
          Threat<span>Mesh</span>
        </span>
      )}
    </div>
  );
}
