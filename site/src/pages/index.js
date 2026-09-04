import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import {useEffect, useState} from 'react';
import styles from './index.module.css';
import {getHomeMessages} from '../home-i18n';

const PATH_COMMANDS = {
  sdk: 'microclaw-sdk = { version = "0.5", features = ["full"] }',
  work: 'brew tap microclaw/tap && brew install --cask microclaw-work',
  server: {
    macos: 'curl -fsSL https://microclaw.org/install.sh | bash',
    linux: 'curl -fsSL https://microclaw.org/install.sh | bash',
    windows: 'iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex',
  },
};

function detectSystem() {
  if (typeof navigator === 'undefined') {
    return 'macos';
  }

  const platform = String(navigator.userAgentData?.platform || navigator.platform || '').toLowerCase();
  const userAgent = String(navigator.userAgent || '').toLowerCase();
  const source = `${platform} ${userAgent}`;

  if (source.includes('win')) {
    return 'windows';
  }
  if (source.includes('mac') || source.includes('darwin')) {
    return 'macos';
  }
  if (source.includes('linux') || source.includes('x11')) {
    return 'linux';
  }
  return 'macos';
}

function HomepageHeader() {
  const {i18n} = useDocusaurusContext();
  const messages = getHomeMessages(i18n.currentLocale);
  const [system, setSystem] = useState('macos');
  const [copiedPath, setCopiedPath] = useState(null);

  useEffect(() => {
    setSystem(detectSystem());
  }, []);

  const copyCommand = async (path, command) => {
    let copied = false;
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(command);
        copied = true;
      } else if (typeof document !== 'undefined') {
        const textarea = document.createElement('textarea');
        textarea.value = command;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        copied = document.execCommand('copy');
        document.body.removeChild(textarea);
      }
    } catch {
      copied = false;
    }

    if (copied) {
      setCopiedPath(path);
      window.setTimeout(() => setCopiedPath(null), 1800);
    }
  };

  const paths = [
    {
      id: 'sdk',
      className: styles.pathCardSdk,
      command: PATH_COMMANDS.sdk,
      href: '/docs/sdk-quickstart',
      ...messages.paths.sdk,
    },
    {
      id: 'work',
      className: styles.pathCardWork,
      command: PATH_COMMANDS.work,
      href: '/docs/work',
      ...messages.paths.work,
    },
    {
      id: 'server',
      className: styles.pathCardServer,
      command: PATH_COMMANDS.server[system] ?? PATH_COMMANDS.server.linux,
      href: '/docs/quickstart',
      environment: messages.systemLabels[system],
      ...messages.paths.server,
    },
  ];

  return (
    <header className={styles.hero}>
      <div className={styles.heroBackdrop} />
      <div className={styles.heroPattern} />
      <div className="container">
        <div className={styles.heroContent}>
          <div className={styles.heroLead}>
            <div className={styles.eyebrow}>{messages.eyebrow}</div>
            <Link className={styles.releasePill} href="https://github.com/microclaw/microclaw/releases/tag/v0.5.5">
              {messages.release} <span aria-hidden="true">→</span>
            </Link>
            <Heading as="h1" className={styles.heroTitle}>
              {messages.heroTitle}
            </Heading>
            <p className={styles.heroSubtitle}>{messages.tagline}</p>
            <p className={styles.heroSubtext}>
              {messages.heroText}
            </p>
            <div className={styles.heroMetaRow}>
              {messages.meta.map((item) => <span key={item}>{item}</span>)}
            </div>
          </div>

          <div className={styles.pathGrid}>
            {paths.map((path, index) => (
              <article key={path.id} className={`${styles.pathCard} ${path.className}`}>
                <div className={styles.pathTopline}>
                  <span className={styles.pathNumber}>0{index + 1}</span>
                  <span className={styles.pathBadge}>{path.badge}</span>
                </div>
                <h2>{path.title}</h2>
                <p className={styles.pathAudience}>{path.audience}</p>
                <p className={styles.pathDescription}>{path.description}</p>
                <ul className={styles.pathBenefits}>
                  {path.benefits.map((benefit) => <li key={benefit}>{benefit}</li>)}
                </ul>
                <div className={styles.pathCommandLabel}>
                  <span>{path.commandLabel}</span>
                  {path.environment && <span>{path.environment}</span>}
                </div>
                <div className={styles.pathCommandRow}>
                  <code>{path.command}</code>
                  <button type="button" onClick={() => copyCommand(path.id, path.command)}>
                    {copiedPath === path.id ? messages.copied : messages.copy}
                  </button>
                </div>
                <Link className={styles.pathAction} to={path.href}>
                  {path.action} <span aria-hidden="true">→</span>
                </Link>
              </article>
            ))}
          </div>
        </div>
      </div>
    </header>
  );
}

function ArchitectureMap({label}) {
  const capabilities = ['Skills', 'Tools + MCP', 'Memory', 'Policy', 'Workers', 'Observability'];

  return (
    <div className={styles.archMap} role="img" aria-label={label}>
      <div className={styles.archEntryRow}>
        <div className={`${styles.archEntry} ${styles.archEntrySdk}`}>
          <span>01 · Embed</span>
          <strong>Rust SDK</strong>
        </div>
        <div className={`${styles.archEntry} ${styles.archEntryWork}`}>
          <span>02 · Desktop</span>
          <strong>MicroClaw Work</strong>
        </div>
        <div className={`${styles.archEntry} ${styles.archEntryServer}`}>
          <span>03 · Service</span>
          <strong>MicroClaw Server</strong>
        </div>
      </div>

      <div className={styles.archConnector} aria-hidden="true">
        <span />
        <em>one shared core</em>
        <span />
      </div>

      <div className={styles.archEngine}>
        <span>PROVIDER-NEUTRAL RUNTIME</span>
        <strong>MicroClaw Agent Engine</strong>
        <p>Agent Loop · Run lifecycle · Events · Recovery</p>
      </div>

      <div className={styles.archCapabilityGrid}>
        {capabilities.map((capability) => (
          <span key={capability}>{capability}</span>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const {siteConfig, i18n} = useDocusaurusContext();
  const messages = getHomeMessages(i18n.currentLocale);

  return (
    <Layout
      title={`${siteConfig.title}`}
      description={messages.description}>
      <HomepageHeader />

      <main>
        <section className={styles.proofStrip}>
          <div className="container">
            <div className={styles.proofGrid}>
              {messages.proof.map(([label, text]) => (
                <div key={label}>
                  <span className={styles.proofLabel}>{label}</span>
                  <p>{text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.section}>
          <div className="container">
            <div className={styles.sectionHeader}>
              <Heading as="h2">{messages.whyTitle}</Heading>
              <p>{messages.whyText}</p>
            </div>
            <div className={styles.capabilityGrid}>
              {messages.capabilities.map(([title, text]) => (
                <article key={title} className={styles.capabilityCard}>
                  <h3>{title}</h3>
                  <p>{text}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionHeader}>
              <Heading as="h2">{messages.architectureTitle}</Heading>
              <p>{messages.architectureText}</p>
            </div>
            <div className={styles.archLayout}>
              <div className={styles.archVisualCard}>
                <ArchitectureMap label={messages.architectureAlt} />
              </div>
              <div className={styles.archSteps}>
                {messages.architectureSteps.map(([title, text], index) => (
                  <article key={title} className={styles.stepCard}>
                    <span>{String(index + 1).padStart(2, '0')}</span>
                    <h3>{title}</h3>
                    <p>{text}</p>
                  </article>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className={styles.section}>
          <div className="container">
            <div className={styles.sectionHeader}>
              <Heading as="h2">{messages.useCasesTitle}</Heading>
              <p>{messages.useCasesText}</p>
            </div>
            <div className={styles.useCaseGrid}>
              {messages.useCases.map(([title, text, href]) => (
                <article key={title} className={styles.useCaseCard}>
                  <h3>{title}</h3>
                  <p>{text}</p>
                  <Link to={href || '/docs/overview'}>{messages.readDetails}</Link>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.finalCta}>
          <div className="container">
            <div className={styles.ctaCard}>
              <div>
                <Heading as="h2">{messages.ctaTitle}</Heading>
                <p>{messages.ctaText}</p>
              </div>
              <div className={styles.ctaActions}>
                <Link className="button button--primary button--lg" to="/docs/quickstart">
                  {messages.quickstartCta}
                </Link>
                <Link className="button button--secondary button--lg" to="/docs/architecture">
                  {messages.architectureDocs}
                </Link>
                <Link className="button button--secondary button--lg" to="/docs/sdk">
                  {messages.sdkDocs}
                </Link>
                <Link className={styles.inlineLink} to="/docs/generated-tools">
                  {messages.toolsReference}
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
