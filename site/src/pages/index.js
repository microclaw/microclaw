import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import {useEffect, useMemo, useState} from 'react';
import styles from './index.module.css';
import {getHomeMessages} from '../home-i18n';

const SYSTEMS = [
  {id: 'macos', label: 'macOS', icon: 'macos'},
  {id: 'windows', label: 'Windows', icon: 'windows'},
  {id: 'linux', label: 'Linux', icon: 'linux'},
];

const INSTALL_OPTIONS_BY_SYSTEM = {
  macos: [
    {
      id: 'install-script',
      labelKey: 'script',
      command: 'curl -fsSL https://microclaw.org/install.sh | bash',
      hintKey: 'macScript',
    },
    {
      id: 'homebrew',
      labelKey: 'brew',
      command: 'brew tap microclaw/tap && brew install microclaw',
      hintKey: 'brew',
    },
    {
      id: 'cargo',
      labelKey: 'cargo',
      command:
        'git clone https://github.com/microclaw/microclaw.git && cd microclaw && cargo build --release',
      hintKey: 'source',
    },
  ],
  windows: [
    {
      id: 'install-script',
      labelKey: 'powershell',
      command: 'iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex',
      hintKey: 'windowsScript',
    },
    {
      id: 'cargo',
      labelKey: 'cargo',
      command:
        'git clone https://github.com/microclaw/microclaw.git; cd microclaw; cargo build --release',
      hintKey: 'source',
    },
  ],
  linux: [
    {
      id: 'install-script',
      labelKey: 'script',
      command: 'curl -fsSL https://microclaw.org/install.sh | bash',
      hintKey: 'linuxScript',
    },
    {
      id: 'cargo',
      labelKey: 'cargo',
      command:
        'git clone https://github.com/microclaw/microclaw.git && cd microclaw && cargo build --release',
      hintKey: 'source',
    },
  ],
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
  const [activeSystem, setActiveSystem] = useState('macos');
  const [activeInstall, setActiveInstall] = useState(
    INSTALL_OPTIONS_BY_SYSTEM.macos[0].id,
  );
  const [copyStatus, setCopyStatus] = useState('idle');

  useEffect(() => {
    const system = detectSystem();
    const fallbackInstall = INSTALL_OPTIONS_BY_SYSTEM[system]?.[0]?.id ?? INSTALL_OPTIONS_BY_SYSTEM.macos[0].id;
    setActiveSystem(system);
    setActiveInstall(fallbackInstall);
  }, []);

  const activeSystemOptions = useMemo(
    () => INSTALL_OPTIONS_BY_SYSTEM[activeSystem] ?? INSTALL_OPTIONS_BY_SYSTEM.macos,
    [activeSystem],
  );

  const activeInstallOption = useMemo(
    () => activeSystemOptions.find((item) => item.id === activeInstall) ?? activeSystemOptions[0],
    [activeInstall, activeSystemOptions],
  );

  const copyInstallCommand = async () => {
    let copied = false;
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(activeInstallOption.command);
        copied = true;
      } else if (typeof document !== 'undefined') {
        const textarea = document.createElement('textarea');
        textarea.value = activeInstallOption.command;
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
      setCopyStatus('copied');
      window.setTimeout(() => setCopyStatus('idle'), 1800);
    }
  };

  return (
    <header className={styles.hero}>
      <div className={styles.heroBackdrop} />
      <div className={styles.heroPattern} />
      <div className="container">
        <div className={styles.heroLayout}>
          <div className={styles.heroContent}>
            <div className={styles.eyebrow}>{messages.eyebrow}</div>
            <Heading as="h1" className={styles.heroTitle}>
              {messages.heroTitle}
            </Heading>
            <p className={styles.heroSubtitle}>{messages.tagline}</p>
            <p className={styles.heroSubtext}>
              {messages.heroText}
            </p>

            <div className={styles.heroActions}>
              <Link className="button button--primary button--lg" to="/docs/quickstart">
                {messages.start}
              </Link>
              <Link className={styles.darkButton} href="https://github.com/microclaw/microclaw">
                {messages.github}
              </Link>
            </div>

            <div className={styles.heroMetaRow}>
              {messages.meta.map((item) => <span key={item}>{item}</span>)}
            </div>
          </div>

          <div className={styles.installPanel}>
            <div className={styles.installHeader}>
              <span>{messages.quickstart}</span>
              <span className={styles.crabLane}>
                <span className={styles.pulseDot} aria-label="rust">
                  🦀
                </span>
              </span>
            </div>
            <div className={styles.systemSwitcher}>
              <div className={styles.systemTabs}>
                {SYSTEMS.map((system) => (
                  <button
                    key={system.id}
                    type="button"
                    onClick={() => {
                      const fallbackInstall = INSTALL_OPTIONS_BY_SYSTEM[system.id]?.[0]?.id;
                      setActiveSystem(system.id);
                      if (fallbackInstall) {
                        setActiveInstall(fallbackInstall);
                      }
                    }}
                    className={`${styles.systemTab} ${
                      activeSystem === system.id ? styles.systemTabActive : ''
                    }`}>
                    <span
                      className={`${styles.systemIcon} ${
                        system.icon === 'macos'
                          ? styles.systemIconMac
                          : system.icon === 'windows'
                            ? styles.systemIconWindows
                            : styles.systemIconLinux
                      }`}
                    />
                    {system.label}
                  </button>
                ))}
              </div>
            </div>
            <div className={styles.installTabs}>
              {activeSystemOptions.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveInstall(item.id)}
                  className={`${styles.installTab} ${
                    activeInstall === item.id ? styles.installTabActive : ''
                  }`}>
                  {messages.installLabels[item.labelKey]}
                </button>
              ))}
            </div>
            <p className={styles.installHint}>{messages.installHints[activeInstallOption.hintKey]}</p>
            <div className={styles.installRow}>
              <code className={styles.installCommand}>{activeInstallOption.command}</code>
              <button
                className={`${styles.copyButton} ${copyStatus === 'copied' ? styles.copyButtonCopied : ''}`}
                type="button"
                onClick={copyInstallCommand}>
                {copyStatus === 'copied' ? messages.copied : messages.copy}
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
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
                <img
                  src="/img/blog/microclaw-runtime/01-system-architecture.svg"
                  alt={messages.architectureAlt}
                />
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
              {messages.useCases.map(([title, text]) => (
                <article key={title} className={styles.useCaseCard}>
                  <h3>{title}</h3>
                  <p>{text}</p>
                  <Link to="/docs/overview">{messages.readDetails}</Link>
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
